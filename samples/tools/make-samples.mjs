/* Generates the samples/ fixtures. Run: node samples/tools/make-samples.mjs
   Every byte of every file is computed here; the parser tests assert the
   exact values written, so parser and samples can't silently drift. */

import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ElfBuilder, SHT, PT, PF, STT, STB, DT } from './elf-build.mjs';

const outDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const HEXCODE = [0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05];   // mov eax,60; syscall (exit)
const DATA = [0xde, 0xad, 0xbe, 0xef];

function fileSection(builder, content) {
  const b = builder.addSection({ name: '.text', type: SHT.PROGBITS, flags: SHT !== undefined ? 0x6 : 0, content, align: 16, vaddr: 'auto' });
  return b;
}

/* 1 — classic no-PIE executable: ET_EXEC, NX on, no RELRO, with .symtab */
function exeNoPie() {
  const b = new ElfBuilder({ type: 2, entry: 0x4000e0 });
  const strtab = b.addStringSection('.strtab');
  const text = b.addSection({ name: '.text', type: SHT.PROGBITS, flags: 0x6, content: new Uint8Array(HEXCODE), align: 16, vaddr: 0x4000e0 });
  const data = b.addSection({ name: '.data', type: SHT.PROGBITS, flags: 0x3, content: new Uint8Array(DATA), align: 8, vaddr: 0x4000f0 });
  const symtab = b.addSection({ name: '.symtab', type: SHT.SYMTAB, link: strtab, info: 1, align: 8, entsize: 24 });
  b.addSymbol(symtab, { nameOff: 0 });                                     // null symbol
  const mainOff = b.strOffset(strtab, 'main');
  b.addSymbol(symtab, { nameOff: mainOff, value: 0x4000e0, size: 7, type: STT.FUNC, bind: STB.GLOBAL, shndx: text });
  const dataOff = b.strOffset(strtab, 'answer');
  b.addSymbol(symtab, { nameOff: dataOff, value: 0x4000f0, size: 4, type: STT.OBJECT, bind: STB.GLOBAL, shndx: data });

  b.addProgram({ type: PT.LOAD, flags: PF.R | PF.X, offset: (placed) => 0, filesz: (placed) => placed.find((s) => s.name === '.data')._offset + 4, vaddr: 0x400000, align: 0x1000 });
  b.addProgram({ type: PT.GNU_STACK, flags: PF.R | PF.W, filesz: 0, align: 16 });   // no X → NX enabled
  return b.build();
}

/* 2 — hardened shared object: ET_DYN (PIE), NX, full RELRO, canary, libc dep */
function pieFullRelro() {
  const b = new ElfBuilder({ type: 3, entry: 0 });
  const dynstr = b.addStringSection('.dynstr');
  const neededOff = b.strOffset(dynstr, 'libc.so.6');
  const canaryOff = b.strOffset(dynstr, '__stack_chk_fail');
  const dynsym = b.addSection({ name: '.dynsym', type: SHT.DYNSYM, link: dynstr, info: 1, align: 8, entsize: 24 });
  b.addSymbol(dynsym, { nameOff: 0 });
  b.addSymbol(dynsym, { nameOff: canaryOff, value: 0, size: 0, type: STT.FUNC, bind: STB.GLOBAL, shndx: 0 });

  const dynamic = b.addSection({ name: '.dynamic', type: SHT.DYNAMIC, link: dynstr, align: 8, entsize: 16, vaddr: 'auto' });
  b.addDynamic(dynamic, DT.NEEDED, neededOff);
  b.addDynamic(dynamic, DT.STRTAB, 0);        // patched below via placeholder — real layout:
  b.addDynamic(dynamic, DT.BIND_NOW, 0);
  b.addDynamic(dynamic, DT.FLAGS, 0x8);       // DF_BIND_NOW
  b.addDynamic(dynamic, DT.NULL, 0);

  const text = b.addSection({ name: '.text', type: SHT.PROGBITS, flags: 0x6, content: new Uint8Array(HEXCODE), align: 16, vaddr: 'auto' });

  const dynamicPlaced = (placed) => placed.find((s) => s.name === '.dynamic');
  b.addProgram({ type: PT.LOAD, flags: PF.R | PF.X, offset: () => 0, filesz: (placed) => placed.find((s) => s.name === '.text')._offset + 7, vaddr: 0x400000, align: 0x1000 });
  b.addProgram({ type: PT.DYNAMIC, flags: PF.R, offset: (p) => dynamicPlaced(p)._offset, filesz: (p) => dynamicPlaced(p)._size, vaddr: (p) => dynamicPlaced(p)._vaddr, align: 8 });
  b.addProgram({ type: PT.GNU_RELRO, flags: PF.R, offset: (p) => dynamicPlaced(p)._offset, filesz: (p) => dynamicPlaced(p)._size, vaddr: (p) => dynamicPlaced(p)._vaddr, align: 1 });
  b.addProgram({ type: PT.GNU_STACK, flags: PF.R | PF.W, filesz: 0, align: 16 });
  return b.build();
}

/* 3 — relocatable object with .rela.text */
function relocObject() {
  const b = new ElfBuilder({ type: 1 });
  const strtab = b.addStringSection('.strtab');
  const symtab = b.addSection({ name: '.symtab', type: SHT.SYMTAB, link: strtab, info: 2, align: 8, entsize: 24 });
  b.addSymbol(symtab, { nameOff: 0 });
  const text = b.addSection({ name: '.text', type: SHT.PROGBITS, flags: 0x6, content: new Uint8Array([0xe8, 0, 0, 0, 0, 0xc3]), align: 4 });
  const helperOff = b.strOffset(strtab, 'helper');
  const helperIdx = b.addSymbol(symtab, { nameOff: helperOff, value: 0, size: 7, type: STT.FUNC, bind: STB.GLOBAL, shndx: text });
  const rela = b.addSection({ name: '.rela.text', type: SHT.RELA, link: symtab, info: text, align: 8, entsize: 24 });
  b.addRela(rela, { offset: 1, sym: helperIdx, type: 2, addend: -4 });   // R_X86_64_PC32
  return b.build();
}

/* 4 — ELF32 LSB executable */
function elf32() {
  const b = new ElfBuilder({ bits: 32, type: 2, entry: 0x8048000, baseAddr: 0x8048000, machine: 3 });
  b.addSection({ name: '.text', type: SHT.PROGBITS, flags: 0x6, content: new Uint8Array([0x90, 0xf4]), align: 16, vaddr: 0x8048054 });
  b.addProgram({ type: PT.LOAD, flags: PF.R | PF.X, offset: () => 0, filesz: (placed) => placed.find((s) => s.name === '.text')._offset + 2, vaddr: 0x8048000, align: 0x1000 });
  b.addProgram({ type: PT.GNU_STACK, flags: PF.R | PF.W, filesz: 0, align: 16 });
  return b.build();
}

/* 5 — NX disabled: PT_GNU_STACK is R+W+X */
function nxDisabled() {
  const b = new ElfBuilder({ type: 2, entry: 0x4000e0 });
  b.addSection({ name: '.text', type: SHT.PROGBITS, flags: 0x6, content: new Uint8Array(HEXCODE), align: 16, vaddr: 0x4000e0 });
  b.addProgram({ type: PT.LOAD, flags: PF.R | PF.X, offset: () => 0, filesz: (placed) => placed.find((s) => s.name === '.text')._offset + 7, vaddr: 0x400000, align: 0x1000 });
  b.addProgram({ type: PT.GNU_STACK, flags: PF.R | PF.W | PF.X, filesz: 0, align: 16 });  // W+X → NX off
  return b.build();
}

/* 6 — corrupt: first 24 bytes of the no-PIE executable */
function truncated(full) {
  return full.slice(0, 24);
}

const samples = {
  'exe-nopie-nx.elf': exeNoPie(),
  'pie-full-relro-canary.elf': pieFullRelro(),
  'reloc.o': relocObject(),
  'elf32-lsb.elf': elf32(),
  'nx-disabled.elf': nxDisabled(),
};
samples['truncated.elf'] = truncated(samples['exe-nopie-nx.elf']);

mkdirSync(outDir, { recursive: true });
for (const [name, bytes] of Object.entries(samples)) {
  writeFileSync(join(outDir, name), bytes);
  console.log(`${name.padEnd(28)} ${bytes.length} bytes`);
}
console.log('samples written');
