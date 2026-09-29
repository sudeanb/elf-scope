# Sample binaries

All files here are **generated** by `tools/make-samples.mjs`, which writes
every byte of every ELF by hand (no compiler involved). They double as the
parser's test fixtures — the tests assert the exact values the generator
wrote, so parser and samples cannot drift apart.

| file | class | type | demonstrates |
|---|---|---|---|
| `exe-nopie-nx.elf` | ELF64 | EXEC | no PIE, NX on, no RELRO, `.symtab` with `main`/`answer` |
| `pie-full-relro-canary.elf` | ELF64 | DYN | PIE, NX, full RELRO (GNU_RELRO + BIND_NOW), `__stack_chk_fail` canary, `DT_NEEDED libc.so.6` |
| `reloc.o` | ELF64 | REL | `.rela.text` with one `R_X86_64_PC32` against `helper`, addend −4 |
| `elf32-lsb.elf` | ELF32 | EXEC | 32-bit path: 52-byte ehdr, 32-byte phdrs, 40-byte shdrs |
| `nx-disabled.elf` | ELF64 | EXEC | `PT_GNU_STACK` R+W+X → NX off |
| `truncated.elf` | ELF64 | — | first 24 bytes of `exe-nopie-nx.elf`; parser must reject with an offset |

Regenerate: `node samples/tools/make-samples.mjs`
