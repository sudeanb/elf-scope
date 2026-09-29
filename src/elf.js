/* ELF32/ELF64 parser — pure JS over Uint8Array, both endiannesses, no
   dependencies, browser + Node parity. Covers: ident, header, section
   headers (+names), program headers, .symtab/.dynsym, .rela/.rel,
   .dynamic (+resolved strings), and the GNU property phdrs the security
   report needs. Truncated or corrupt files throw ElfError with offsets. */

import { ByteReader, ElfError } from './reader.js';

export const SHT_NAMES = {
  0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA', 5: 'HASH',
  6: 'DYNAMIC', 7: 'NOTE', 8: 'NOBITS', 9: 'REL', 10: 'SHLIB', 11: 'DYNSYM', 14: 'INIT_ARRAY', 15: 'FINI_ARRAY',
};
export const PT_NAMES = {
  0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 5: 'SHLIB', 6: 'PHDR', 7: 'TLS',
  0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO', 0x6474e553: 'GNU_PROPERTY',
};
export const DT_NAMES = {
  0: 'NULL', 1: 'NEEDED', 2: 'PLTRELSZ', 3: 'PLTGOT', 4: 'HASH', 5: 'STRTAB', 6: 'SYMTAB', 7: 'RELA',
  8: 'RELASZ', 9: 'RELAENT', 10: 'STRSZ', 11: 'SYMENT', 14: 'SONAME', 15: 'RPATH', 20: 'PLTREL',
  24: 'BIND_NOW', 27: 'RELCOUNT', 29: 'RUNPATH', 30: 'FLAGS', 0x6ffffdf5: 'GNU_HASH', 0x6ffffffb: 'FLAGS_1', 0x6ffffff0: 'VERSYM',
};
export const DF_FLAGS = { 0x1: 'ORIGIN', 0x2: 'SYMBOLIC', 0x4: 'TEXTREL', 0x8: 'BIND_NOW', 0x10: 'STATIC_TLS' };
export const DF_1_FLAGS = { 0x1: 'NOW', 0x2: 'GLOBAL', 0x4: 'GROUP', 0x8: 'NODELETE' };
export const R_X86_64 = {
  0: 'R_X86_64_NONE', 1: 'R_X86_64_64', 2: 'R_X86_64_PC32', 3: 'R_X86_64_GOT32', 4: 'R_X86_64_PLT32',
  5: 'R_X86_64_COPY', 6: 'R_X86_64_GLOB_DAT', 7: 'R_X86_64_JUMP_SLOT', 8: 'R_X86_64_RELATIVE', 9: 'R_X86_64_GOTPCREL',
};
export const R_386 = {
  0: 'R_386_NONE', 1: 'R_386_32', 2: 'R_386_PC32', 3: 'R_386_GOT32', 4: 'R_386_PLT32', 8: 'R_386_RELATIVE',
};
export const STT_NAMES = { 0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION', 4: 'FILE' };
export const STB_NAMES = { 0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK' };
export const ET_NAMES = { 0: 'NONE', 1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE' };
const SHT_SYMTAB = 2, SHT_STRTAB = 3, SHT_RELA = 4, SHT_DYNAMIC = 6, SHT_DYNSYM = 11, SHT_REL = 9;

export function parseElf(bytes) {
  const r = new ByteReader(bytes);
  if (r.length < 16) throw new ElfError('file shorter than the ELF ident (16 bytes)', 0);
  r.seek(0);
  const magic = [...r.bytesAt(0, 4, 'ELF magic')];
  if (magic[0] !== 0x7f || magic[1] !== 0x45 || magic[2] !== 0x4c || magic[3] !== 0x46) {
    throw new ElfError('not an ELF file: magic \\x7fELF missing');
  }
  r.seek(4);
  const eiClass = r.u8('EI_CLASS');
  if (eiClass !== 1 && eiClass !== 2) throw new ElfError(`bad EI_CLASS ${eiClass}`);
  const eiData = r.u8('EI_DATA');
  if (eiData !== 1 && eiData !== 2) throw new ElfError(`bad EI_DATA ${eiData}`);
  const bits = eiClass === 2 ? 64 : 32;
  const endian = eiData === 1 ? 'lsb' : 'msb';
  const lr = new ByteReader(bytes, endian);   // reader with the file's endianness
  const ident = {
    eiClass: bits === 64 ? 'ELF64' : 'ELF32',
    eiData: endian === 'lsb' ? 'LSB' : 'MSB',
    eiVersion: r.u8('EI_VERSION'),
    eiOsabi: r.u8('EI_OSABI'),
  };

  const is64 = bits === 64;
  lr.seek(16);
  const header = {
    eType: lr.u16('e_type'),
    eMachine: lr.u16('e_machine'),
    eVersion: lr.u32('e_version'),
    eEntry: is64 ? Number(lr.u64('e_entry')) : lr.u32('e_entry'),
    ePhoff: is64 ? Number(lr.u64('e_phoff')) : lr.u32('e_phoff'),
    eShoff: is64 ? Number(lr.u64('e_shoff')) : lr.u32('e_shoff'),
    eFlags: lr.u32('e_flags'),
    eEhsize: lr.u16('e_ehsize'),
    ePhentsize: lr.u16('e_phentsize'),
    ePhnum: lr.u16('e_phnum'),
    eShentsize: lr.u16('e_shentsize'),
    eShnum: lr.u16('e_shnum'),
    eShstrndx: lr.u16('e_shstrndx'),
  };

  // section headers
  const shdrs = [];
  for (let i = 0; i < header.eShnum; i++) {
    if (header.eShoff + (i + 1) * header.eShentsize > bytes.length) {
      throw new ElfError(`truncated file: section header ${i} past end of file`, Number(header.eShoff) + i * header.eShentsize);
    }
    lr.seek(Number(header.eShoff) + i * header.eShentsize);
    const nameOff = lr.u32('sh_name');
    shdrs.push({
      nameOff,
      type: lr.u32('sh_type'),
      flags: is64 ? lr.u64('sh_flags') : lr.u32('sh_flags'),
      addr: is64 ? lr.u64('sh_addr') : lr.u32('sh_addr'),
      offset: is64 ? lr.u64('sh_offset') : lr.u32('sh_offset'),
      size: is64 ? lr.u64('sh_size') : lr.u32('sh_size'),
      link: lr.u32('sh_link'),
      info: lr.u32('sh_info'),
      addralign: is64 ? lr.u64('sh_addralign') : lr.u32('sh_addralign'),
      entsize: is64 ? lr.u64('sh_entsize') : lr.u32('sh_entsize'),
    });
  }
  const shstrtab = shdrs[header.eShstrndx];
  if (!shstrtab) throw new ElfError(`e_shstrndx ${header.eShstrndx} out of range`);
  const nameReader = new ByteReader(bytes, endian);
  for (const s of shdrs) {
    s.name = nameReader.cstrAt(Number(shstrtab.offset) + s.nameOff, 'section name');
    s.typeName = SHT_NAMES[s.type] ?? `0x${s.type.toString(16)}`;
  }

  // program headers
  const phdrs = [];
  for (let i = 0; i < header.ePhnum; i++) {
    if (Number(header.ePhoff) + (i + 1) * header.ePhentsize > bytes.length) {
      throw new ElfError(`truncated file: program header ${i} past end of file`, Number(header.ePhoff) + i * header.ePhentsize);
    }
    lr.seek(Number(header.ePhoff) + i * header.ePhentsize);
    let p;
    if (is64) {
      p = { type: lr.u32('p_type'), flags: lr.u32('p_flags') };
      p.offset = lr.u64('p_offset'); p.vaddr = lr.u64('p_vaddr'); p.paddr = lr.u64('p_paddr');
      p.filesz = lr.u64('p_filesz'); p.memsz = lr.u64('p_memsz'); p.align = lr.u64('p_align');
    } else {
      p = { type: lr.u32('p_type'), offset: lr.u32('p_offset'), vaddr: lr.u32('p_vaddr'), paddr: lr.u32('p_paddr'), filesz: lr.u32('p_filesz'), memsz: lr.u32('p_memsz'), flags: lr.u32('p_flags'), align: lr.u32('p_align') };
    }
    p.typeName = PT_NAMES[p.type] ?? `0x${p.type.toString(16)}`;
    p.flagNames = [p.flags & 4 && 'R', p.flags & 2 && 'W', p.flags & 1 && 'X'].filter(Boolean).join('') || '-';
    phdrs.push(p);
  }

  // symbol tables (.symtab, .dynsym)
  const readSymbols = (sec) => {
    const out = [];
    const strSec = shdrs[sec.link];
    if (!strSec) throw new ElfError(`symbol table ${sec.name} has bad sh_link ${sec.link}`);
    const entsize = Number(sec.entsize) || (is64 ? 24 : 16);
    const count = Math.floor(Number(sec.size) / entsize);
    for (let i = 0; i < count; i++) {
      lr.seek(Number(sec.offset) + i * entsize);
      let sym;
      if (is64) {
        const nameOff = lr.u32('st_name');
        const info = lr.u8('st_info');
        const other = lr.u8('st_other');
        const shndx = lr.u16('st_shndx');
        sym = { nameOff, stInfo: info, stOther: other, shndx, value: lr.u64('st_value'), size: lr.u64('st_size') };
        sym.visibility = other & 3;
      } else {
        const nameOff = lr.u32('st_name');
        const value = lr.u32('st_value');
        const size = lr.u32('st_size');
        const info = lr.u8('st_info');
        const other = lr.u8('st_other');
        const shndx = lr.u16('st_shndx');
        sym = { nameOff, value, size, stInfo: info, stOther: other, shndx, visibility: other & 3 };
      }
      sym.bind = STB_NAMES[sym.stInfo >> 4] ?? String(sym.stInfo >> 4);
      sym.type = STT_NAMES[sym.stInfo & 0xf] ?? String(sym.stInfo & 0xf);
      sym.name = sym.nameOff ? nameReader.cstrAt(Number(strSec.offset) + sym.nameOff, 'symbol name') : '';
      out.push(sym);
    }
    return out;
  };
  const symtabSec = shdrs.find((s) => s.type === SHT_SYMTAB);
  const dynsymSec = shdrs.find((s) => s.type === SHT_DYNSYM);
  const symtab = symtabSec ? readSymbols(symtabSec) : null;
  const dynsym = dynsymSec ? readSymbols(dynsymSec) : null;

  // relocations (.rela.*, .rel.*) — named for x86-64 and i386
  const relocs = [];
  for (const sec of shdrs) {
    if (sec.type !== SHT_RELA && sec.type !== SHT_REL) continue;
    const symSec = shdrs[sec.link];
    const entsize = Number(sec.entsize) || (sec.type === SHT_RELA ? (is64 ? 24 : 12) : is64 ? 16 : 8);
    const count = Math.floor(Number(sec.size) / entsize);
    for (let i = 0; i < count; i++) {
      lr.seek(Number(sec.offset) + i * entsize);
      let rel;
      if (is64) {
        const offset = lr.u64('r_offset');
        const info = lr.u64('r_info');
        const sym = Number(info >> 32n);
        const type = Number(info & 0xffffffffn);
        rel = { section: sec.name, offset, sym, type, target: sec.info };
        if (sec.type === SHT_RELA) rel.addend = Number(lr.i64('r_addend'));
      } else {
        const offset = lr.u32('r_offset');
        const info = lr.u32('r_info');
        rel = { section: sec.name, offset, sym: info >> 8, type: info & 0xff, target: sec.info };
      }
      rel.typeName = (header.eMachine === 62 ? R_X86_64 : header.eMachine === 3 ? R_386 : {})[rel.type] ?? `R_${rel.type}`;
      if (symSec) {
        const strSec = shdrs[symSec.link];
        const symEntsize = Number(symSec.entsize) || (is64 ? 24 : 16);
        lr.seek(Number(symSec.offset) + rel.sym * symEntsize);
        const nameOff = lr.u32('st_name');
        rel.symbol = symSec.type === SHT_SYMTAB || symSec.type === SHT_DYNSYM
          ? (nameOff && strSec ? nameReader.cstrAt(Number(strSec.offset) + nameOff, 'reloc symbol') : '')
          : '';
      }
      relocs.push(rel);
    }
  }

  // .dynamic — tags resolved to names + strings where they reference the dynstr
  const dynamicSec = shdrs.find((s) => s.type === SHT_DYNAMIC);
  let dynamic = null;
  if (dynamicSec) {
    const strSec = shdrs[dynamicSec.link];
    const entsize = Number(dynamicSec.entsize) || (is64 ? 16 : 8);
    const count = Math.floor(Number(dynamicSec.size) / entsize);
    dynamic = [];
    for (let i = 0; i < count; i++) {
      lr.seek(Number(dynamicSec.offset) + i * entsize);
      const tag = is64 ? Number(lr.i64('d_tag')) : lr.u32('d_tag');
      const val = is64 ? lr.u64('d_val') : lr.u32('d_un');
      const entry = { tag, name: DT_NAMES[tag] ?? `0x${tag.toString(16)}`, val };
      if (strSec && (tag === 1 || tag === 14 || tag === 15 || tag === 29)) {
        entry.string = nameReader.cstrAt(Number(strSec.offset) + Number(val), 'dynamic string');
      }
      dynamic.push(entry);
    }
  }

  const needed = dynamic?.filter((d) => d.tag === 1).map((d) => d.string) ?? [];
  const gnuStack = phdrs.find((p) => p.type === 0x6474e551) ?? null;
  const gnuRelro = phdrs.find((p) => p.type === 0x6474e552) ?? null;
  const interp = phdrs.find((p) => p.type === 3) ?? null;

  return {
    bits, endian, ident, header,
    bytes,
    type: header.eType, typeName: ET_NAMES[header.eType] ?? String(header.eType),
    machine: header.eMachine,
    sections: shdrs,
    findSection: (name) => shdrs.find((s) => s.name === name) ?? null,
    programHeaders: phdrs,
    symtab, dynsym, relocs, dynamic, needed,
    gnuStack, gnuRelro, interp,
  };
}
