# Kernel config recovery

The curated kernel-CVE checklist ([cve-join.md](cve-join.md)) gates each bug on the `CONFIG` options its
subsystem needs. That gate is only as good as our knowledge of the target's kernel configuration. A kernel
built with `CONFIG_IKCONFIG` embeds its gzipped `.config` (recovered by `kconfig.cpp`), but most vendor
kernels disable it to save flash. Without a config, every in-range kernel CVE degrades to "config unknown"
and the checklist is just a version match — noise.

This module (`kconfig_infer.cpp`, `kallsyms.cpp`) recovers config knowledge from whatever the image *does*
carry, so the gate keeps working when IKCONFIG is absent.

## Sources, in descending trust

| # | Source | What it proves | Rules in | Rules out |
|---|--------|----------------|:--------:|:---------:|
| 1 | A real `.config` — IKCONFIG, or an on-disk `/boot/config-*` / dumped `/proc/config.gz` | `=y`/`=m` enabled, `# … is not set` disabled | ✅ | ✅ (authoritative: anything not enabled is off) |
| 2a | `/lib/modules/<ver>/modules.builtin` | which modules are built in (`=y`) | ✅ | — |
| 2b | Loadable `.ko` files under `/lib/modules` | which subsystems ship as modules (`=m`) | ✅ | — |
| 3 | Decoded **kallsyms** symbol table | built-in subsystems (their functions are named symbols) | ✅ | ✅ *(complete table only, see below)* |
| 4 | Distinctive strings in the kernel image | a subsystem is probably present | ✅ (weak) | — |

Each source contributes to a `KernelConfigView`. `config_option_state()` reads the merged view back per
option as **On** / **Off** / **Unknown**, with the evidence label that decided it; `kernel_cve_scan()` turns
those into applicable / ruled-out / undetermined verdicts.

## The evidence model (why tri-state)

Positive evidence is easy: a symbol, a module, or a `=y` line proves a subsystem is compiled in. Negative
evidence is the subtle part, because *absence* has two causes — the subsystem is off, or it is a module we
have not looked inside.

- A recovered `.config` is **authoritative**: an option that is not enabled is genuinely off.
- On a **complete** kallsyms table, a missing built-in symbol means the subsystem is not built in. For a
  subsystem that can only ever be built in (`CONFIG_IO_URING`, `CONFIG_USER_NS`, `CONFIG_CGROUPS`,
  `CONFIG_BPF_SYSCALL`, `CONFIG_KEYS`, `CONFIG_PERF_EVENTS`, `CONFIG_POSIX_MQUEUE`), that is a definitive
  **rule-out** on its own.
- For a subsystem that can be a module (`mac80211`, `nf_tables`, `bluetooth`, `dccp`, `tipc`, …), a missing
  symbol only rules it out when we *also* saw a `/lib/modules` tree and the module is not in it
  (`kallsyms+modules`). Otherwise it stays **Unknown** — never falsely ruled out.

This is the whole point: the checklist tells the operator what it *knows* is exploitable, what it *knows* is
ruled out, and what it genuinely *cannot* determine, instead of dumping every version match as "unknown" or,
worse, ruling bugs out on incomplete evidence.

Example, the same MIPS 3.10.14 camera kernel, two ways:

```
# whole rootfs (ships /etc/kernel.config): authoritative
18 applicable kernel CVEs (of 42 in range)  [24 ruled out, 0 undetermined]   config: recovered .config

# the bare kernel image alone: kallsyms only
18 applicable kernel CVEs (of 42 in range)  [4 ruled out, 20 undetermined]   config: inferred (kallsyms/modules/strings)
```

The bare-kernel run rules out only the built-in-only subsystems it can prove absent (io_uring, user_ns,
cgroups, posix_mqueue) and leaves the modular ones undetermined — the honest answer without the rootfs.

## The kallsyms decoder (`kallsyms.cpp`)

`CONFIG_KALLSYMS=y` (on in almost every production kernel) embeds a table of every built-in symbol name, the
source of `/proc/kallsyms`. The names are **token-compressed**: a 256-entry token table plus, per symbol, a
length byte and a run of token-index bytes that share a type-char prefix. A plain `strings(1)` sweep recovers
only a lucky few, so we decode the table properly. The decoder is self-anchoring and works on a raw,
decompressed kernel image with no ELF symbols, any architecture, 32- or 64-bit, little- or big-endian words:

1. **Token tables.** Scan for `kallsyms_token_index`: 256 little-endian `uint16` starting at 0 and strictly
   increasing by small steps. Validate by recovering `kallsyms_token_table` right before it (256
   NUL-terminated tokens) and checking every index lands on a token boundary.
2. **Names, via the address array (fast path).** `kallsyms_addresses` / `kallsyms_offsets` is a monotonic run
   of `num_syms` words; the word just after it *equals* `num_syms`, and `kallsyms_names` follows. That
   value-equals-length coincidence is a decisive anchor — decode `num_syms` names from there and accept only
   if core symbols (`commit_creds`, …) appear.
3. **Names, via markers (fallback).** For base-relative kernels whose offset array is not a plain monotonic
   run, locate `kallsyms_markers` (offsets increasing from 0, just before the token table); `markers[1]` is
   the byte length of the first 256 symbols, an O(256) gate that pins `kallsyms_names` without a wide search.

Symbol lengths are capped and every read is bounds-checked, so a malformed or truncated image yields *no*
table rather than a crash — verified with ASan/UBSan across real payloads, random data, and truncations. A
failed or partial decode simply leaves those options Unknown; it never fabricates a symbol, so it never
causes a false rule-out.

## Outputs

- **Human** — a `config:` posture line (source + option count); a separate **Kernel hardening** section,
  one feature per line with a tri-state tag `[enabled]` (green) / `[disabled]` (red — present but off, a
  finding) / `[not available]` (dim — the option did not exist in this kernel version); and the kernel-CVE
  verdicts colored by meaning: applicable = red (exploitable surface), ruled out = green (surface removed),
  undetermined = dim.
- **JSON** — a `kernel_config` object (always emitted with `--cve`): `source`, `recovered`,
  `options_enabled`, `hardening[]` (per-feature tri-state `enabled`/`disabled`/`not_available`), and
  `options[]` — the per-gating-option `{name, state, evidence}` audit trail behind every `kernel_cves`
  verdict. Hardening feature detection covers the CONFIG renames across kernel versions (e.g. the stack
  protector's `CC_STACKPROTECTOR*` → `STACKPROTECTOR*`), so an old kernel is not misreported as unhardened.
- **`--dump-kconfig`** — prints the verbatim recovered `.config` (IKCONFIG or on-disk) to stdout and exits;
  nonzero when none was recovered. Power-user escape hatch for the full config; the report never inlines all
  4,000-odd options.

## Adding a gated option

The knowledge table is in `kconfig_infer.cpp` (`knowledge()`). One entry per `CONFIG` option the CVE table
gates on, giving: the built-in **function symbols** unique to the subsystem (the kallsyms oracle — pick
internal functions, not `sys_*` syscall wrappers, which are name-mangled per arch), the **module** base
names (`.ko` / `modules.builtin`), any distinctive **strings**, and whether the subsystem is **builtin-only**
(so a complete kallsyms without it is a rule-out). Add the CVE to `kernelcve.cpp` with the same option in its
`req`/`mit`, and the gate picks it up.
