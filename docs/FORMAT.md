# The ELF format, field by field

Reference for what `src/elf.js` reads, with byte offsets. "u32" = unsigned
32-bit little-endian in this file's byte order (LSB or MSB, chosen by
`EI_DATA`); ELF64 fields that differ from ELF32 are marked.

## e_ident (16 bytes, file offset 0)

| offset | field | values |
|---|---|---|
| 0–3 | magic | `7f 45 4c 46` (`\x7fELF`) |
| 4 | EI_CLASS | 1 = ELF32, 2 = ELF64 |
| 5 | EI_DATA | 1 = LSB, 2 = MSB |
| 6 | EI_VERSION | 1 |
| 7 | EI_OSABI | 0 = SYSV, 3 = Linux, 6 = Solaris … |
| 8–15 | padding | zero |

## ELF header (64 bytes in ELF64, 52 in ELF32)

| ELF64 offset | field | meaning |
|---|---|---|
| 16 | e_type (u16) | 1 REL (object), 2 EXEC (no PIE), 3 DYN (PIE / shared object) |
| 18 | e_machine (u16) | 62 = x86-64, 3 = i386 |
| 20 | e_version (u32) | 1 |
| 24 | e_entry (u64) | virtual address of the entry point |
| 32 | e_phoff (u64) | file offset of the program header table (0 if none) |
| 40 | e_shoff (u64) | file offset of the section header table |
| 48 | e_flags (u32) | machine-specific |
| 52 | e_ehsize (u16) | 64 |
| 54 | e_phentsize (u16) | 56 in ELF64, 32 in ELF32 |
| 56 | e_phnum (u16) | program header count |
| 58 | e_shentsize (u16) | 64 in ELF64, 40 in ELF32 |
| 60 | e_shnum (u16) | section header count |
| 62 | e_shstrndx (u16) | section index of `.shstrtab` |

## Program header (56 bytes ELF64: type u32, flags u32, then six u64s)

| field | meaning |
|---|---|
| p_type | 1 LOAD, 2 DYNAMIC, 3 INTERP, 4 NOTE, 6 PHDR, 7 TLS, 0x6474e551 GNU_STACK, 0x6474e552 GNU_RELRO |
| p_flags | 1 = X, 2 = W, 4 = R |
| p_offset / p_vaddr / p_paddr | where the segment sits in the file / memory |
| p_filesz / p_memsz | segment size in the file / in memory (BSS grows) |
| p_align | alignment |

What the security report reads from these: `GNU_STACK` flags (W+X ⇒ NX
off), `GNU_RELRO` presence (+ `BIND_NOW` ⇒ full RELRO), `INTERP` + `ET_DYN`
⇒ PIE.

## Section header (64 bytes ELF64)

| field | meaning |
|---|---|
| sh_name (u32) | byte offset of the name inside `.shstrtab` |
| sh_type (u32) | 1 PROGBITS, 2 SYMTAB, 3 STRTAB, 4 RELA, 6 DYNAMIC, 8 NOBITS, 9 REL, 11 DYNSYM |
| sh_flags (u64) | 1 WRITE, 2 ALLOC, 4 EXECINSTR |
| sh_addr / sh_offset / sh_size | memory address / file position / size |
| sh_link (u32) | for SYMTAB: the string table section; for RELA: the symbol table |
| sh_info (u32) | for RELA: the section the relocations apply to; for SYMTAB: first non-local index |
| sh_entsize (u64) | 24 for ELF64 symbol entries, 24 for RELA64 |

## Symbols (24 bytes ELF64: name u32, info u8, other u8, shndx u16, value u64, size u64)

- `st_info` high nibble = bind (0 LOCAL, 1 GLOBAL, 2 WEAK), low nibble = type
  (1 OBJECT, 2 FUNC, 4 FILE)
- entry 0 is always the null symbol; string-table offset 0 is the empty name

## Relocations

- RELA64 (24 bytes): `r_offset` u64, `r_info` u64 = (symbol << 32) \| type,
  `r_addend` s64
- x86-64 types: 1 `R_X86_64_64`, 2 `R_X86_64_PC32`, 4 `R_X86_64_PLT32`,
  6 `R_X86_64_GLOB_DAT`, 7 `R_X86_64_JUMP_SLOT`, 8 `R_X86_64_RELATIVE`

## .dynamic (16 bytes ELF64: tag s64, val u64)

| tag | meaning |
|---|---|
| DT_NEEDED (1) | val = offset of a library name in `.dynstr` |
| DT_SONAME (14), DT_RPATH (15), DT_RUNPATH (29) | strings as well |
| DT_BIND_NOW (24) | resolve all relocations at load time |
| DT_FLAGS (30) | bit 0x8 = BIND_NOW |
| DT_FLAGS_1 (0x6ffffffb) | bit 0x1 = NOW |

Full RELRO = `PT_GNU_RELRO` present **and** one of DT_BIND_NOW /
DT_FLAGS BIND_NOW / DT_FLAGS_1 NOW.

## Modeled simplifications

- `src/walk`-style raw PTE bits are not decoded — the parser exposes the
  semantic fields (this repo has no PTEs; that's mmu-lab).
- 64-bit values that cannot be `Number` (huge addresses) stay BigInt;
  everything the security report compares is small.
