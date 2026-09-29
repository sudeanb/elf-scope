/* Analysis layer over the parsed ELF: dependency graph, security report,
   hex-view annotations. All pure functions over the parseElf() model. */

import { DF_FLAGS, DF_1_FLAGS } from './elf.js';

export function dependencyGraph(elf) {
  const nodes = [{ id: '<main>', kind: 'main' }];
  for (const n of elf.needed) nodes.push({ id: n, kind: 'needed' });
  const edges = elf.needed.map((n) => ({ from: '<main>', to: n }));
  const soname = elf.dynamic?.find((d) => d.tag === 14)?.string;
  if (soname) nodes[0].soname = soname;
  return { nodes, edges, runpath: runpathOf(elf), rpath: rpathOf(elf) };
}

export function runpathOf(elf) {
  return elf.dynamic?.find((d) => d.tag === 29)?.string ?? null;
}

export function rpathOf(elf) {
  return elf.dynamic?.find((d) => d.tag === 15)?.string ?? null;
}

/* Security posture: the classic hardening checklist. status ∈ good/warn/bad/info. */
export function securityReport(elf) {
  const checks = [];

  // PIE
  const isDyn = elf.type === 3;
  const isExec = elf.type === 2;
  checks.push({
    name: 'PIE',
    status: isDyn ? 'good' : isExec ? 'bad' : 'info',
    detail: isDyn
      ? `ET_DYN${elf.interp ? ' + PT_INTERP → PIE executable' : ' → shared object'}`
      : isExec ? 'ET_EXEC — fixed load address, no ASLR for the main image' : `e_type ${elf.type}`,
  });

  // NX (stack not executable)
  if (elf.gnuStack) {
    const w = Boolean(elf.gnuStack.flags & 2);
    const x = Boolean(elf.gnuStack.flags & 1);
    checks.push({
      name: 'NX',
      status: w && x ? 'bad' : 'good',
      detail: `PT_GNU_STACK flags ${elf.gnuStack.flagNames}${w && x ? ' — stack is writable AND executable' : ' — stack not executable'}`,
    });
  } else {
    checks.push({ name: 'NX', status: 'info', detail: 'no PT_GNU_STACK header (old toolchains); kernels usually default to NX' });
  }

  // RELRO
  if (elf.gnuRelro) {
    const bindNow = elf.dynamic?.some((d) => d.tag === 24 || (d.tag === 30 && Number(d.val) & 0x8) || (d.tag === 0x6ffffffb && Number(d.val) & 0x1));
    checks.push({
      name: 'RELRO',
      status: bindNow ? 'good' : 'warn',
      detail: bindNow ? 'PT_GNU_RELRO + BIND_NOW → full RELRO (GOT read-only after load)' : 'PT_GNU_RELRO without BIND_NOW → partial RELRO (GOT still writable)',
    });
  } else {
    checks.push({ name: 'RELRO', status: 'bad', detail: 'no PT_GNU_RELRO — GOT is writable at runtime' });
  }

  // stack canary
  const canary = (elf.dynsym ?? []).some((s) => s.name === '__stack_chk_fail') || (elf.symtab ?? []).some((s) => s.name === '__stack_chk_fail');
  checks.push({
    name: 'canary',
    status: canary ? 'good' : 'warn',
    detail: canary ? '__stack_chk_fail referenced — stack protector linked in' : 'no __stack_chk_fail reference — compiled without stack protector?',
  });

  // RPATH / RUNPATH
  const rpath = rpathOf(elf);
  const runpath = runpathOf(elf);
  if (rpath) checks.push({ name: 'RPATH', status: 'warn', detail: `DT_RPATH = ${rpath} (deprecated, overrides LD_LIBRARY_PATH)` });
  if (runpath) checks.push({ name: 'RUNPATH', status: 'info', detail: `DT_RUNPATH = ${runpath}` });

  // symbols
  const stripped = !elf.symtab;
  checks.push({
    name: 'symbols',
    status: stripped ? 'info' : 'info',
    detail: stripped ? 'stripped — no .symtab' : `not stripped — ${elf.symtab.length - 1} symbol(s) in .symtab`,
  });

  return { checks, score: checks.filter((c) => c.status === 'good').length, total: checks.length };
}

/* Byte ranges annotated with the structure they hold, for the hex view. */
export function hexAnnotations(elf) {
  const { bits } = elf;
  const ranges = [];
  const ehsize = bits === 64 ? 64 : 52;
  ranges.push({ start: 0, end: ehsize, label: 'ELF header', kind: 'header' });
  if (elf.header.ePhnum) {
    ranges.push({
      start: Number(elf.header.ePhoff),
      end: Number(elf.header.ePhoff) + elf.header.ePhnum * elf.header.ePhentsize,
      label: 'program headers', kind: 'phdr',
    });
  }
  for (const s of elf.sections) {
    if (s.type === 8 || s.offset === 0 || s.size === 0) continue;    // NOBITS / null
    if (Number(s.offset) + Number(s.size) > elfSize(elf)) continue;  // synthetic ranges
    ranges.push({ start: Number(s.offset), end: Number(s.offset) + Number(s.size), label: s.name, kind: 'section' });
  }
  ranges.sort((a, b) => a.start - b.start);
  return ranges;
}

function elfSize(elf) {
  return elf.header.eShoff && elf.sections.length
    ? Number(elf.header.eShoff) + elf.header.eShnum * elf.header.eShentsize
    : Infinity;
}

/* Hex dump rows with per-byte annotation membership. */
export function hexView(elf, { limit = 512 } = {}) {
  const ranges = hexAnnotations(elf);
  const rows = [];
  const size = Math.min(limit, elfSize(elf));
  for (let base = 0; base < size; base += 16) {
    const labels = new Set();
    const row = [];
    for (let i = 0; i < 16 && base + i < size; i++) {
      const at = base + i;
      row.push(at < elf.bytes.length ? elf.bytes[at] : null);
      const hit = ranges.find((rg) => at >= rg.start && at < rg.end);
      if (hit) labels.add(hit.label);
    }
    rows.push({ offset: base, bytes: row, labels: [...labels] });
  }
  return { rows, ranges };
}
