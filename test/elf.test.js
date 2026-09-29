import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseElf, SHT_NAMES } from '../src/elf.js';
import { ByteReader, ElfError } from '../src/reader.js';
import { securityReport, dependencyGraph, hexAnnotations, hexView } from '../src/analyze.js';
import { ElfBuilder, SHT, PT, PF } from '../samples/tools/elf-build.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const load = (f) => parseElf(readFileSync(join(root, 'samples', f)));

test('exe-nopie-nx: header, sections and symbols parse exactly as generated', () => {
  const e = load('exe-nopie-nx.elf');
  assert.equal(e.ident.eiClass, 'ELF64');
  assert.equal(e.ident.eiData, 'LSB');
  assert.equal(e.typeName, 'EXEC');
  assert.equal(e.machine, 62);
  assert.equal(e.header.eEntry, 0x4000e0);
  assert.deepEqual(e.sections.map((s) => s.name),
    ['', '.strtab', '.text', '.data', '.symtab', '.shstrtab']);
  const main = e.symtab[1], answer = e.symtab[2];
  assert.equal(main.name, 'main');
  assert.equal(main.type, 'FUNC');
  assert.equal(main.bind, 'GLOBAL');
  assert.equal(main.value, 0x4000e0n);
  assert.equal(main.size, 7n);
  assert.equal(answer.name, 'answer');
  assert.equal(answer.type, 'OBJECT');
  // section content round-trips byte for byte
  const text = e.findSection('.text');
  assert.deepEqual([...e.bytes.slice(Number(text.offset), Number(text.offset) + 7)],
    [0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05]);
});

test('exe-nopie-nx: program headers and security posture', () => {
  const e = load('exe-nopie-nx.elf');
  assert.deepEqual(e.programHeaders.map((p) => p.typeName), ['LOAD', 'GNU_STACK']);
  assert.equal(e.programHeaders[0].flagNames, 'RX');
  assert.equal(e.programHeaders[1].flagNames, 'RW');
  const rep = Object.fromEntries(securityReport(e).checks.map((c) => [c.name, c.status]));
  assert.equal(rep.PIE, 'bad');        // ET_EXEC
  assert.equal(rep.NX, 'good');        // stack RW, not RWX
  assert.equal(rep.RELRO, 'bad');      // no PT_GNU_RELRO
  assert.equal(rep.canary, 'warn');    // no __stack_chk_fail
  const details = Object.fromEntries(securityReport(e).checks.map((c) => [c.name, c.detail]));
  assert.match(details.symbols, /not stripped/);
});

test('pie-full-relro-canary: full hardening detected', () => {
  const e = load('pie-full-relro-canary.elf');
  assert.equal(e.typeName, 'DYN');
  assert.deepEqual(e.needed, ['libc.so.6']);
  assert.equal(e.dynsym[1].name, '__stack_chk_fail');
  const tags = e.dynamic.map((d) => d.name);
  assert.ok(tags.includes('BIND_NOW'));
  assert.ok(tags.includes('FLAGS'));
  const rep = Object.fromEntries(securityReport(e).checks.map((c) => [c.name, c.status]));
  assert.equal(rep.PIE, 'good');
  assert.equal(rep.NX, 'good');
  assert.equal(rep.RELRO, 'good');     // PT_GNU_RELRO + BIND_NOW
  assert.equal(rep.canary, 'good');
  const g = dependencyGraph(e);
  assert.deepEqual(g.nodes.map((n) => n.id), ['<main>', 'libc.so.6']);
  assert.deepEqual(g.edges, [{ from: '<main>', to: 'libc.so.6' }]);
});

test('reloc.o: relocation decodes type name, symbol and addend', () => {
  const e = load('reloc.o');
  assert.equal(e.typeName, 'REL');
  assert.equal(e.relocs.length, 1);
  const r = e.relocs[0];
  assert.equal(r.section, '.rela.text');
  assert.equal(r.typeName, 'R_X86_64_PC32');
  assert.equal(r.symbol, 'helper');
  assert.equal(r.addend, -4);
  assert.equal(r.offset, 1n);
  assert.equal(e.symtab[1].name, 'helper');
});

test('elf32-lsb.elf: 32-bit path parses', () => {
  const e = load('elf32-lsb.elf');
  assert.equal(e.bits, 32);
  assert.equal(e.header.eEhsize, 52);
  assert.equal(e.header.ePhentsize, 32);
  assert.equal(e.header.eShentsize, 40);
  assert.equal(e.programHeaders[0].typeName, 'LOAD');
  const text = e.findSection('.text');
  assert.equal(text.typeName, 'PROGBITS');
});

test('nx-disabled.elf: W+X stack is flagged bad', () => {
  const e = load('nx-disabled.elf');
  const nx = securityReport(e).checks.find((c) => c.name === 'NX');
  assert.equal(nx.status, 'bad');
  assert.match(nx.detail, /writable AND executable/);
});

test('every generated sample is valid and section contents stay in bounds', () => {
  const files = readdirSync(join(root, 'samples'))
    .filter((f) => (f.endsWith('.elf') || f.endsWith('.o')) && !f.startsWith('truncated'));
  assert.ok(files.length >= 5);
  for (const f of files) {
    const bytes = readFileSync(join(root, 'samples', f));
    const e = parseElf(bytes);
    for (const s of e.sections) {
      if (s.type === 8 || s.size === 0) continue;                     // NOBITS
      assert.ok(Number(s.offset) + Number(s.size) <= bytes.length, `${f}:${s.name} in bounds`);
    }
  }
});

test('truncated files throw with the byte offset', () => {
  for (const cut of [8, 24, 40, 48]) {
    const full = readFileSync(join(root, 'samples/exe-nopie-nx.elf'));
    try {
      parseElf(full.slice(0, cut));
      assert.fail(`cut ${cut} should have thrown`);
    } catch (err) {
      assert.ok(err instanceof ElfError);
      assert.equal(typeof err.offset, 'number');
    }
  }
  try {
    parseElf(new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99]));
    assert.fail('bad shoff should throw');
  } catch (err) { assert.ok(err instanceof ElfError); }
});

test('non-ELF input is rejected by magic', () => {
  assert.throws(() => parseElf(new TextEncoder().encode('MZ definitely not elf')), /magic/);
  assert.throws(() => parseElf(new Uint8Array(4)), /magic|shorter/);
});

test('MSB (big-endian) files parse via the same path', () => {
  const b = new ElfBuilder({ endian: 'msb', type: 2, entry: 0x1000_0040 });
  b.addSection({ name: '.text', type: SHT.PROGBITS, flags: 0x6, content: new Uint8Array([0x01, 0x02]), align: 4, vaddr: 0x1000_0040 });
  b.addProgram({ type: PT.LOAD, flags: PF.R | PF.X, offset: 0, filesz: 96, vaddr: 0x1000_0000 });
  b.addProgram({ type: PT.GNU_STACK, flags: PF.R | PF.W, filesz: 0 });
  const e = parseElf(b.build());
  assert.equal(e.ident.eiData, 'MSB');
  assert.equal(e.typeName, 'EXEC');
  assert.equal(e.findSection('.text').typeName, 'PROGBITS');
  assert.equal(e.programHeaders[0].typeName, 'LOAD');
});

test('SHT names cover the sections the samples use', () => {
  assert.equal(SHT_NAMES[2], 'SYMTAB');
  assert.equal(SHT_NAMES[11], 'DYNSYM');
});

test('hexAnnotations cover header + program table + sections in order', () => {
  const e = load('exe-nopie-nx.elf');
  const rg = hexAnnotations(e);
  assert.equal(rg[0].label, 'ELF header');
  assert.ok(rg.some((r) => r.label === 'program headers'));
  assert.ok(rg.some((r) => r.label === '.text' && r.end - r.start === 7));
  const sorted = [...rg].sort((a, b) => a.start - b.start);
  assert.deepEqual(rg, sorted);
  const view = hexView(e, { limit: 64 });
  assert.equal(view.rows.length, 4);
  assert.equal(view.rows[0].bytes[0], 0x7f);
});

test('dependency graph: object with no deps has just the main node', () => {
  const g = dependencyGraph(load('reloc.o'));
  assert.deepEqual(g.nodes.map((n) => n.id), ['<main>']);
  assert.deepEqual(g.edges, []);
});

test('CLI info/security output', () => {
  const out = execFileSync('node', ['bin/elfscope.js', 'security', 'samples/pie-full-relro-canary.elf'],
    { cwd: root, encoding: 'utf8' });
  assert.match(out, /PIE/);
  assert.match(out, /full RELRO/);
  assert.match(out, /canary/);
  const info = execFileSync('node', ['bin/elfscope.js', 'info', 'samples/reloc.o'], { cwd: root, encoding: 'utf8' });
  assert.match(info, /ELF64/);
  assert.match(info, /REL/);
  const json = execFileSync('node', ['bin/elfscope.js', 'info', 'samples/elf32-lsb.elf', '--json'], { cwd: root, encoding: 'utf8' });
  const parsed = JSON.parse(json);
  assert.equal(parsed.bits, 32);
});

test('CLI rejects bad files with a non-zero exit', () => {
  assert.throws(() => execFileSync('node', ['bin/elfscope.js', 'info', 'samples/truncated.elf'], { cwd: root, encoding: 'utf8' }),
    /Command failed/);
  assert.throws(() => execFileSync('node', ['bin/elfscope.js', 'info', 'README.md'], { cwd: root, encoding: 'utf8' }),
    /Command failed/);
});

test('reader endianness basics', () => {
  const lsb = new ByteReader(new Uint8Array([1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 'lsb');
  assert.equal(lsb.u32(), 1);
  const msb = new ByteReader(new Uint8Array([0, 0, 0, 1]), 'msb');
  assert.equal(msb.u32(), 1);
  lsb.seek(14);
  assert.throws(() => lsb.u32('past end'), ElfError);
});
