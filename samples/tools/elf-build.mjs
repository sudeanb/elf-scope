/* Minimal ELF builder — emits real, valid ELF binaries byte by byte.
   Used to generate samples/ fixtures: the parser's tests assert against
   values this builder wrote, and the builder computes every field
   (offsets, string tables, link/info) explicitly, so validity is by
   construction. Supports the small subset the samples need:
   ELF32/ELF64, LSB, ET_EXEC/ET_DYN/ET_REL, phdrs, shdrs, symtab/dynsym,
   strtab, dynamic, rela. */

const SHT = { NULL: 0, PROGBITS: 1, SYMTAB: 2, STRTAB: 3, RELA: 4, DYNAMIC: 6, DYNSYM: 11 };
const PT = { LOAD: 1, DYNAMIC: 2, GNU_STACK: 0x6474e551, GNU_RELRO: 0x6474e552 };
const PF = { X: 1, W: 2, R: 4 };
const STT = { NOTYPE: 0, OBJECT: 1, FUNC: 2, FILE: 3 };
const STB = { LOCAL: 0, GLOBAL: 1, WEAK: 2 };
const DT = { NULL: 0, NEEDED: 1, STRTAB: 5, SYMTAB: 6, STRSZ: 10, SYMENT: 11, BIND_NOW: 24, FLAGS: 30 };

class ByteBuf {
  constructor(endian) { this.endian = endian; this.bytes = []; }
  w8(v) { this.bytes.push(v & 0xff); return this; }
  w16(v) { const parts = this.endian === 'lsb' ? [0, 8] : [8, 0]; for (const sh of parts) this.w8((v >> sh) & 0xff); return this; }
  w32(v) { const order = this.endian === 'lsb' ? [0, 1, 2, 3] : [3, 2, 1, 0]; for (const i of order) this.w8((v >> (i * 8)) & 0xff); return this; }
  w64(v) { const b = BigInt(v); const order = this.endian === 'lsb' ? [0, 1, 2, 3, 4, 5, 6, 7] : [7, 6, 5, 4, 3, 2, 1, 0]; for (const i of order) this.w8(Number((b >> BigInt(i * 8)) & 0xffn)); return this; }
  raw(bytes) { for (const b of bytes) this.w8(b); return this; }
  cstr(s) { for (const c of Buffer.from(s, 'latin1')) this.w8(c); this.w8(0); return this; }
  get length() { return this.bytes.length; }
  toU8() { return new Uint8Array(this.bytes); }
}

const align = (n, a) => (a <= 1 ? n : Math.ceil(n / a) * a);

export class ElfBuilder {
  constructor({ bits = 64, endian = 'lsb', type, machine = 62, entry = 0, baseAddr = 0x400000 } = {}) {
    this.bits = bits; this.endian = endian; this.type = type; this.machine = machine;
    this.entry = entry; this.base = BigInt(baseAddr);
    this.sections = [{
      // ELF reserves section index 0 for the NULL section — seed it so
      // addSection() returns real file indices.
      name: '', type: SHT.NULL, flags: 0, align: 0, entsize: 0, link: 0, info: 0, vaddr: 0,
      content: new ByteBuf(endian),
    }];
    this.phdrs = [];                 // {type,flags,offset|fn,vaddr|'auto',filesz,memsz,align}
  }

  addSection({ name, type, flags = 0, content = null, align: al = 1, entsize = 0, link = 0, info = 0, vaddr = 0 }) {
    this.sections.push({ name, type, flags, align: al, entsize, link, info, vaddr, content: content ?? new ByteBuf(this.endian) });
    return this.sections.length - 1;
  }

  addStringSection(name) {
    const content = new ByteBuf(this.endian);
    content.w8(0);                     // ELF convention: string-table offset 0 is the empty name
    this.sections.push({ name, type: SHT.STRTAB, flags: 0, align: 1, entsize: 0, link: 0, info: 0, vaddr: 0, content });
    return this.sections.length - 1;
  }

  strOffset(secIndex, s) {
    const b = this.sections[secIndex].content;
    const off = b.length;
    b.cstr(s);
    return off;
  }

  addSymbol(secIndex, { nameOff, value = 0, size = 0, type = STT.NOTYPE, bind = STB.LOCAL, shndx = 0, other = 0 }) {
    const b = this.sections[secIndex].content;
    if (this.bits === 64) b.w32(nameOff).w8((bind << 4) | type).w8(other).w16(shndx).w64(value).w64(size);
    else b.w32(nameOff).w32(value).w32(size).w8((bind << 4) | type).w8(other).w16(shndx);
    return b.length / (this.bits === 64 ? 24 : 16) - 1;   // symbol index
  }

  addRela(secIndex, { offset = 0, sym = 0, type = 0, addend = 0 }) {
    const b = this.sections[secIndex].content;
    if (this.bits === 64) b.w64(offset).w64((BigInt(sym) << 32n) | BigInt(type)).w64(BigInt(addend));
    else b.w32(offset).w32((sym << 8) | type);
  }

  addDynamic(secIndex, tag, val = 0) {
    const b = this.sections[secIndex].content;
    if (this.bits === 64) b.w64(BigInt(tag)).w64(BigInt(val));
    else b.w32(tag).w32(val);
  }

  addProgram({ type, flags, offset = 0, filesz = 0, memsz = null, align = 8, vaddr = 0 }) {
    this.phdrs.push({ type, flags, offset, filesz, memsz: memsz ?? filesz, align, vaddr });
    return this.phdrs.length - 1;
  }

  build() {
    const bits = this.bits;
    const ehsize = bits === 64 ? 64 : 52;
    const phentsize = bits === 64 ? 56 : 32;
    const shentsize = bits === 64 ? 64 : 40;
    const asBuf = (c) => {
      if (c instanceof ByteBuf) return c;
      const b = new ByteBuf(this.endian);
      return b.raw(c);
    };

    // layout: [ehdr][phdrs][section contents…][shstrtab][shdrs]
    let cursor = align(ehsize + this.phdrs.length * phentsize, 16);
    const placed = [];
    for (const s of this.sections) {
      if (s.type === SHT.NULL) { placed.push({ ...s, _offset: 0, _size: 0, _vaddr: 0 }); continue; }
      cursor = align(cursor, s.align || 1);
      placed.push({
        ...s,
        _offset: cursor,
        _size: s.content.length,
        _vaddr: s.vaddr === 'auto' ? Number(this.base + BigInt(cursor)) : s.vaddr,
      });
      cursor += s.content.length;
    }
    const shstr = new ByteBuf(this.endian);
    shstr.cstr('');
    const nameOff = placed.map((s) => {
      const off = shstr.length;
      shstr.cstr(s.name);
      return off;
    });
    const shstrIndex = placed.length;
    nameOff.push((() => { const off = shstr.length; shstr.cstr('.shstrtab'); return off; })());
    placed.push({ name: '.shstrtab', type: SHT.STRTAB, flags: 0, align: 1, entsize: 0, link: 0, info: 0, vaddr: 0, content: shstr, _offset: cursor, _size: shstr.length, _vaddr: 0 });
    const shstrFileIndex = placed.length - 1;   // includes the NULL section
    cursor += shstr.length;
    const shoff = align(cursor, 8);

    for (const p of this.phdrs) {
      p._offset = typeof p.offset === 'function' ? p.offset(placed) : p.offset;
      p._vaddr = typeof p.vaddr === 'function' ? p.vaddr(placed)
        : (p.vaddr === 'auto' ? Number(this.base + BigInt(p._offset)) : p.vaddr);
      p._filesz = typeof p.filesz === 'function' ? p.filesz(placed) : p.filesz;
      p._memsz = typeof p.memsz === 'function' ? p.memsz(placed) : (p.memsz ?? p._filesz);
    }

    const blob = new ByteBuf(this.endian);

    // ehdr
    const e = new ByteBuf(this.endian);
    e.w8(0x7f).w8(0x45).w8(0x4c).w8(0x46);          // \x7fELF
    e.w8(bits === 64 ? 2 : 1).w8(this.endian === 'lsb' ? 1 : 2).w8(1).w8(0);
    for (let i = 0; i < 8; i++) e.w8(0);
    e.w16(this.type).w16(this.machine).w32(1);
    const phoff = this.phdrs.length ? ehsize : 0;
    if (bits === 64) {
      e.w64(this.entry).w64(BigInt(phoff)).w64(BigInt(shoff)).w32(0);
    } else {
      e.w32(this.entry).w32(phoff).w32(shoff).w32(0);
    }
    e.w16(ehsize).w16(phentsize).w16(this.phdrs.length).w16(shentsize).w16(placed.length).w16(shstrFileIndex);
    if (e.length !== ehsize) throw new Error(`ehdr size ${e.length} != ${ehsize}`);
    blob.raw(e.toU8());

    // phdrs
    const ph = new ByteBuf(this.endian);
    for (const p of this.phdrs) {
      if (bits === 64) {
        ph.w32(p.type).w32(p.flags).w64(BigInt(p._offset)).w64(BigInt(p._vaddr))
          .w64(BigInt(p._vaddr)).w64(BigInt(p._filesz)).w64(BigInt(p._memsz)).w64(BigInt(p.align));
      } else {
        ph.w32(p.type).w32(p._offset).w32(p._vaddr).w32(p._vaddr)
          .w32(p._filesz).w32(p._memsz).w32(p.flags).w32(p.align);
      }
    }
    blob.raw(ph.toU8());

    // contents
    const padTo = (pos) => { while (blob.length < pos) blob.w8(0); };
    for (const s of placed) {
      if (s.type === SHT.NULL) continue;
      padTo(s._offset);
      blob.raw(asBuf(s.content).toU8());
    }
    padTo(shoff);

    // shdrs — placed[0] is the NULL section, its fields are all zero
    const sh = new ByteBuf(this.endian);
    for (const s of placed) {
      if (bits === 64) {
        sh.w32(nameOff[placed.indexOf(s)]).w32(s.type).w64(BigInt(s.flags)).w64(BigInt(s._vaddr))
          .w64(BigInt(s._offset)).w64(BigInt(s._size)).w32(s.link).w32(s.info).w64(BigInt(s.align)).w64(BigInt(s.entsize));
      } else {
        sh.w32(nameOff[placed.indexOf(s)]).w32(s.type).w32(s.flags).w32(s._vaddr)
          .w32(s._offset).w32(s._size).w32(s.link).w32(s.info).w32(s.align).w32(s.entsize);
      }
    }
    blob.raw(sh.toU8());
    return blob.toU8();
  }
}

export { SHT, PT, PF, STT, STB, DT };
