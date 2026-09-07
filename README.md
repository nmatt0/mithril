# mithril

**IoT static scanner for secrets, SBOM, CVEs and more.**

mithril analyzes the *contents* of firmware and IoT software, whether a single file or an unpacked rootfs. It looks for four things: embedded secrets and keys, a software bill of materials (SBOM), known CVEs affecting those components, and open-source licenses. It reports each finding with its evidence and a confidence, and it speaks clean JSON so scripts and LLM agents can drive it as easily as people can.

A scan makes no network calls. Secrets, SBOM, and license analysis are fully offline, and the CVE pass reads a local vulnerability mirror you refresh out of band.

mithril is the semantic companion to [moria](https://github.com/nmatt0/moria), which identifies and unpacks firmware. moria maps the bytes. mithril reads the contents.

```
moria -e firmware.bin            # identify + unpack  -> firmware.bin.extracted/
mithril firmware.bin.extracted/  # secrets + SBOM + CVEs + licenses
```

It has no build-time dependency on moria. Point it at any file or directory.

## Why mithril

- **Firmware-aware SBOM.** Beyond package databases (dpkg/opkg/apk/rpm), it recovers components from ELF version banners, versioned libc filenames, and the kernel banner, so it finds openssl/busybox/uClibc even in a stripped image with no package manager. Emitted as CycloneDX and SPDX.
- **CVEs it owns end to end.** A local OSV + NVD/CPE mirror plus a curated, version- and kconfig-gated kernel-CVE checklist. Every match records how sure it is (exact version vs affected range vs CPE), stays release-precise where `/etc/os-release` allows, and is annotated with CISA KEV and EPSS.
- **Honest by construction.** Secrets ride a deterministic offline ladder: `pattern` (shape), then `structural` (a parsed JWT or PEM key), then `validated` (a recomputed checksum, such as GitHub tokens and crypt hashes). mithril asserts well-formed, never "live," and an empty result is a real answer rather than a tool failure.
- **Fully offline and reproducible.** No network at scan time; the CVE mirror is refreshed by an explicit, separate step. Air-gappable.
- **Safe on hostile input.** Untrusted bytes go through one bounds-checked reader. Parsers degrade to a clean error rather than crash, and the CVE index is memory-mapped so a scan never parses the whole thing.

## Build

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

No third-party libraries. Debug with sanitizers: `cmake -S . -B build -DMT_SANITIZE=ON`.

## Install

```
cmake --install build --prefix ~/.local     # or /usr/local (needs sudo)
```

Installs the `mithril` binary. A bare `cp build/mithril ~/.local/bin` works too.

## Usage

Output is human-readable by default. Pass `-j` for JSON.

```
mithril <file|dir>            # run every pass (human-readable)
mithril -j <dir>              # JSON, for tools and agents
mithril --secrets <dir>       # secrets only
mithril --sbom -C out/ <dir>  # SBOM only -> out/sbom.cdx.json + out/sbom.spdx.json
mithril --cve <dir>           # match components against the local mirror (offline)
mithril --licenses <dir>      # licenses only
mithril --rules my.json <dir> # add user-defined rules (docs/user-rules.md)
mithril --fetch-db            # download a prebuilt CVE mirror (fast; a networked command)
mithril --update-db           # rebuild the CVE mirror from source (a networked command)
mithril --help
```

Naming any of `--secrets` / `--sbom` / `--cve` / `--licenses` runs just those. Naming none runs all four.

## The CVE mirror

`--cve` reads a local mirror under `~/.local/share/mithril/` (honors `$MITHRIL_DB`), a compact, memory-mapped index built from OSV.dev, the NVD 2.0 API, the CISA KEV catalog, and FIRST's EPSS scores that a scan loads in a fraction of a second. Get it two ways, and only these two commands ever touch the network:

- **`mithril --fetch-db`** downloads a prebuilt index (rebuilt daily) and verifies every file against a published SHA-256 before installing. This is the fast path: no upstream scraping, a few seconds. Point it at a mirror with `$MITHRIL_DB_URL`.
- **`mithril --update-db`** rebuilds the index from the upstream feeds yourself. Slower, needs `curl` and `unzip`, and is the authoritative path if you want to control exactly what goes in. Set `$NVD_API_KEY` to raise the NVD rate limit (optional; it works without one, just slower).

Build it once either way; every scan after that is offline. See `docs/cve-join.md` and `docs/cve-index-format.md`.

## Scope

- **secrets**: credential and key material in file content (cloud keys, tokens, JWTs, private keys, high-entropy `KEY=…` values). `/etc/shadow` and `htpasswd` hashes are classified with weak-algorithm and empty-password flags, and credential/crypto/config files are flagged by path.
- **sbom**: components and versions from package databases, language manifests, binary version strings, libc filenames, and the kernel banner, keyed on purl (with CPE co-derived), emitted as CycloneDX and SPDX.
- **cve**: the SBOM joined against the local OSV + NVD/CPE mirror, plus the curated kernel-CVE checklist, annotated with KEV and EPSS.
- **licenses**: SPDX identification from `SPDX-License-Identifier` tags and LICENSE/COPYING/NOTICE text.

File-type identification, extraction, and embedded key/certificate *file* signatures are moria's job; mithril reads content, it does not unpack. How discovery works is documented in `docs/engine-design.md`.

## License

MIT, see `LICENSE`. The vulnerability and license data fetched by `--update-db` (OSV.dev, NVD, CISA KEV, FIRST EPSS) belong to their respective sources. mithril mirrors them locally and does not redistribute them.
