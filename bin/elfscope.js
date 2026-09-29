#!/usr/bin/env node
/* elfscope CLI — inspect ELF files from the terminal.
   Commands: info | sections | symbols | dynamic | security | graph | hex */

import { readFileSync } from 'node:fs';
import { parseElf } from '../src/elf.js';
import { securityReport, dependencyGraph, hexView } from '../src/analyze.js';

const args = process.argv.slice(2);
const cmd = args[0];
const file = args[1];
const asJson = args.includes('--json');

function usage() {
  console.error('usage: node bin/elfscope.js <info|sections|symbols|dynamic|security|graph|hex> <file.elf> [--json]');
  process.exit(2);
}
if (!cmd || !file) usage();

let elf;
try {
  elf = parseElf(new Uint8Array(readFileSync(file)));
} catch (err) {
  console.error(`elfscope: ${file}: ${err.message}`);
  process.exit(1);
}

const out = (() => {
  switch (cmd) {
    case 'info': return {
      bits: elf.bits, endian: elf.endian, ident: elf.ident, type: elf.typeName, machine: elf.machine,
      entry: '0x' + elf.header.eEntry.toString(16),
      phnum: elf.header.ePhnum, shnum: elf.header.eShnum,
      sections: elf.sections.map((s) => s.name || '(null)'),
      needed: elf.needed,
    };
    case 'sections': return elf.sections.map((s) => ({
      name: s.name || '(null)', type: s.typeName, flags: s.flags.toString(16),
      offset: Number(s.offset), size: Number(s.size),
    }));
    case 'symbols': {
      const table = elf.symtab ?? elf.dynsym;
      if (!table) return { symbols: [] };
      return table.slice(1).map((s) => ({
        name: s.name, bind: s.bind, type: s.type,
        value: '0x' + s.value.toString(16), size: Number(s.size), shndx: s.shndx,
      }));
    }
    case 'dynamic': return { entries: elf.dynamic ?? [], needed: elf.needed };
    case 'security': return securityReport(elf);
    case 'graph': return dependencyGraph(elf);
    case 'hex': {
      const n = Number(args.includes('-n') ? args[args.indexOf('-n') + 1] : 256);
      return hexView(elf, { limit: n });
    }
    default: usage();
  }
})();

if (asJson) {
  console.log(JSON.stringify(out, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2));
} else if (cmd === 'security') {
  console.log(`⌘ ${file} — ${out.score}/${out.total} hardening checks pass`);
  for (const c of out.checks) {
    const icon = { good: '✓', warn: '!', bad: '✗', info: '·' }[c.status];
    console.log(`  ${icon} ${c.name.padEnd(9)} ${c.detail}`);
  }
} else if (cmd === 'graph') {
  console.log(out.nodes.map((n) => n.id).join(' → '));
  for (const e of out.edges) console.log(`  ${e.from} depends on ${e.to}`);
} else if (cmd === 'hex') {
  for (const row of out.rows) {
    const hex = row.bytes.map((b) => (b ?? 0).toString(16).padStart(2, '0')).join(' ');
    console.log(row.offset.toString(16).padStart(8, '0'), hex, row.labels.join('|'));
  }
} else {
  console.log(JSON.stringify(out, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2));
}
