import { parseElf } from '../src/elf.js';
import { securityReport, dependencyGraph, hexAnnotations } from '../src/analyze.js';

const $ = (id) => document.getElementById(id);

function loadBytes(bytes, name) {
  try {
    const elf = parseElf(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
    render(elf, name);
  } catch (err) {
    $('report').hidden = false;
    for (const pane of document.querySelectorAll('.pane')) pane.innerHTML =
      `<div class="card" style="border-color: var(--red)"><h3>Not a (supported) ELF file</h3><p>${err.message}</p></div>`;
  }
}

function render(elf, name) {
  $('report').hidden = false;

  /* overview */
  $('tab-overview').innerHTML = `
    <div class="card"><h3>${name}</h3>
      <div class="kv">
        <span class="k">class / endian</span><span>${elf.ident.eiClass} · ${elf.ident.eiData}</span>
        <span class="k">type</span><span>${elf.typeName} (${elf.bits}-bit)</span>
        <span class="k">machine</span><span>${elf.machine}</span>
        <span class="k">entry</span><span>0x${elf.header.eEntry.toString(16)}</span>
        <span class="k">program headers</span><span>${elf.header.ePhnum}</span>
        <span class="k">sections</span><span>${elf.header.eShnum}</span>
        <span class="k">needed libs</span><span>${elf.needed.join(', ') || '—'}</span>
        <span class="k">relocations</span><span>${elf.relocs.length}</span>
      </div></div>`;

  /* sections — clicking jumps to the hex view */
  const hexRanges = hexAnnotations(elf);
  const rowToRange = (label) => hexRanges.find((r) => r.label === label);
  $('tab-sections').innerHTML = `<table><thead><tr><th>#</th><th>name</th><th>type</th><th>flags</th><th>offset</th><th>size</th></tr></thead><tbody>` +
    elf.sections.map((s, i) =>
      `<tr class="clickable" data-range="${s.name}"><td>${i}</td><td>${s.name || '(null)'}</td><td>${s.typeName}</td>
       <td>0x${s.flags.toString(16)}</td><td>0x${Number(s.offset).toString(16)}</td><td>${Number(s.size)}</td></tr>`).join('') +
    `</tbody></table>`;

  /* symbols */
  const table = elf.symtab ?? elf.dynsym;
  $('tab-symbols').innerHTML = table
    ? `<table><thead><tr><th>name</th><th>bind</th><th>type</th><th>value</th><th>size</th><th>shndx</th></tr></thead><tbody>` +
      table.slice(1).map((s) =>
        `<tr><td>${s.name || '(unnamed)'}</td><td>${s.bind}</td><td>${s.type}</td>
         <td>0x${s.value.toString(16)}</td><td>${Number(s.size)}</td><td>${s.shndx}</td></tr>`).join('') +
      `</tbody></table><p class="legend">${elf.symtab ? '.symtab' : '.dynsym only (stripped?)'}</p>`
    : '<p class="legend">no symbol tables — stripped?</p>';

  /* dynamic + dependency graph */
  const g = dependencyGraph(elf);
  $('tab-dynamic').innerHTML = `
    <div class="graph">${g.nodes.map((n, i) =>
      (i ? '<span class="arrow">→</span>' : '') + `<span class="node ${n.kind}">${n.id}</span>`).join('')}</div>
    ${g.runpath ? `<p class="legend">RUNPATH ${g.runpath}</p>` : ''}
    <table><thead><tr><th>tag</th><th>value</th></tr></thead><tbody>` +
    (elf.dynamic ?? []).filter((d) => d.tag !== 0).map((d) =>
      `<tr><td>${d.name}</td><td>${d.string ?? d.val}</td></tr>`).join('') +
    `</tbody></table>`;

  /* security */
  const rep = securityReport(elf);
  $('tab-security').innerHTML = `<div class="cards">` +
    rep.checks.map((c) =>
      `<div class="card"><h3><span class="badge ${c.status}">${c.status}</span>${c.name}</h3><p>${c.detail}</p></div>`).join('') +
    `</div><p class="legend">${rep.score}/${rep.total} hardening checks pass</p>`;

  /* hex */
  renderHex(elf, null);

  /* wire tabs + click-to-highlight */
  document.querySelectorAll('.tab').forEach((b) => b.onclick = () => {
    document.querySelectorAll('.tab').forEach((x) => x.classList.remove('active'));
    document.querySelectorAll('.pane').forEach((x) => x.classList.remove('active'));
    b.classList.add('active');
    $('tab-' + b.dataset.tab).classList.add('active');
  });
  document.querySelectorAll('#tab-sections tr.clickable').forEach((tr) => tr.onclick = () => {
    const rg = rowToRange(tr.dataset.range);
    if (rg) { renderHex(elf, rg); switchTab('hex'); }
  });

  function switchTab(id) {
    document.querySelectorAll('.tab').forEach((x) => x.classList.toggle('active', x.dataset.tab === id));
    document.querySelectorAll('.pane').forEach((x) => x.classList.remove('active'));
    $('tab-' + id).classList.add('active');
  }
}

function renderHex(elf, highlight) {
  const rows = [];
  const ranges = hexAnnotations(elf);
  const limit = Math.min(elf.bytes.length, 512);
  for (let base = 0; base < limit; base += 16) {
    let html = base.toString(16).padStart(8, '0') + '  ';
    let labels = new Set();
    for (let i = 0; i < 16; i++) {
      const at = base + i;
      if (at >= limit) { html += '   '; continue; }
      const hit = ranges.find((r) => at >= r.start && at < r.end);
      const inHi = highlight && hit && hit.label === highlight.label;
      if (hit) labels.add(hit.label);
      const byte = elf.bytes[at].toString(16).padStart(2, '0');
      html += (inHi ? `<span class="hl">${byte}</span>` : byte) + ' ';
    }
    html += ' ' + [...labels].join('·');
    rows.push(`<div class="hexrow">${html}</div>`);
  }
  $('tab-hex').innerHTML = `<div class="hex">${rows.join('')}</div>
    <p class="legend">${highlight ? `highlighted: ${highlight.label} — click a section row to switch` : 'click a section in the sections tab to highlight it'}</p>`;
}

/* file input + drag & drop */
$('file').onchange = (e) => {
  const f = e.target.files[0];
  if (f) f.arrayBuffer().then((ab) => loadBytes(new Uint8Array(ab), f.name));
};
const drop = $('drop');
drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
drop.ondragleave = () => drop.classList.remove('over');
drop.ondrop = (e) => {
  e.preventDefault();
  drop.classList.remove('over');
  const f = e.dataTransfer.files[0];
  if (f) f.arrayBuffer().then((ab) => loadBytes(new Uint8Array(ab), f.name));
};
document.querySelectorAll('[data-sample]').forEach((b) => b.onclick = () => {
  fetch('samples/' + b.dataset.sample)
    .then((r) => { if (!r.ok) throw new Error('sample not found'); return r.arrayBuffer(); })
    .then((ab) => loadBytes(new Uint8Array(ab), b.dataset.sample))
    .catch((err) => alert('could not load sample: ' + err.message));
});
