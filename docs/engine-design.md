# mithril engine design — "How To Find Stuff"

The core design decision for mithril: what discovers things in files, and how. This is the reference the
passes are built against. Decided 2026-09-05.

## Principle

mithril is **offline, deterministic, reproducible, air-gappable** — the same trust bar as moria. A scan
makes **no network calls** and needs **no external data at scan time** for secrets, SBOM extraction, and
config discovery. (The CVE join reads a *local* vuln mirror that is refreshed out-of-band; the scan itself
is still offline.) Every finding is evidence-backed and records how strong its basis is.

## The headline: the core is a prefilter → validate pipeline, not a regex

Regex as the primary scanner is rejected: running many patterns over a multi-megabyte image is slow,
regex cannot validate a checksum or parse a key structure, and free-range regex over adversarial firmware
is a ReDoS hazard that would break the fuzzing bar. Regex is a good bounded *extractor*, a poor *scanner*.

The core is the shape moria uses (and TruffleHog before it): **one cheap multi-pattern pass selects
candidates; targeted validators/parsers then confirm and extract.** This is O(n) in the file regardless of
rule count, and all expensive or dangerous work runs on small bounded windows.

## There is no single primitive — there are four matchers (M1–M4)

"How to find stuff" is four distinct matching problems. The engine names them and composes them; it does
not force one hammer on every job.

- **M1 · Path/name match (globs).** Which files are interesting, or are package DBs / credential stores.
  Examples: `etc/shadow`, `**/*.pem`, `**/dropbear_rsa_host_key`, `var/lib/dpkg/status`. O(1) per file.
- **M2 · Content prefilter (Aho-Corasick).** One automaton built from every literal anchor across all
  content rules (`AKIA`, `ghp_`, `-----BEGIN `, `BusyBox v`, `OpenSSL `, `password`). One linear pass over
  the text-ish regions of a file yields candidate offsets. This is the workhorse that keeps big-image
  scans fast and scales to hundreds of anchors.
- **M3 · Validators / extractors (run only on a bounded window around an anchor).** A library of small
  functions that rules reference by name: char-class run, version regex, CRC32 recompute, base64 / utf16le
  / hex decode-then-rescan, JWT decode, PEM/DER parse, Shannon entropy, false-positive wordlist. This is
  where a secret is validated and where a binary version string is pulled.
- **M4 · Format parsers (dispatched by path/magic).** Parse a whole known file into structured records:
  deb822 (dpkg/opkg) and apk → components; `/etc/shadow`, `htpasswd`, `chap-secrets` → credentials; JSON
  language manifests → components.

### The CVE join is deliberately NOT an engine matcher

`(component identity) ⋈ (offline vuln DB)` by purl/CPE plus version-range comparison is a **join and a
comparator**, not a text search. It sits downstream of the SBOM output. Keeping it out of the matcher
model prevents over-generalizing the engine.

## Job → matcher mapping

| Job | Primitives |
|---|---|
| **Secrets** | M2 anchor → M3 validate (char-class + entropy + CRC32/JWT/PEM); M4 for credential-store files (`shadow`, `htpasswd`) |
| **Bins/libs → SBOM** | M4 for package DBs & manifests (structured, high confidence); M2 anchor → M3 version-regex for binary version strings |
| **Interesting configs / IOCs** | M1 path globs + M2/M3 content rules — the home of user-definable rules |
| **CVE from SBOM** | downstream join (purl/CPE lookup + version-range compare), not the engine |

## Pipeline

```
 walk ─▶ file ─▶ M1 path-glob ─┬─ package DB / cred store ─▶ M4 parser ─▶ components / secrets
                               └─ interesting path ────────────────────▶ notable-file
             ─▶ text-ish gate ─▶ M2 Aho-Corasick anchors ─▶ per anchor:
                                                            M3 validate/extract on bounded window
                                                            ─▶ secret / version-string / config-hit
 components ───────────────────────────────────────────────────────────────────┐
                                                                                 ▼
                                            CVE JOIN: purl/CPE lookup + version-range compare
                                            (reads a local offline DB; a comparator, not a search)
```

The **text-ish gate** (already implemented for secrets) skips high-entropy compressed/encrypted regions so
a mostly-compressed image does not pay for pointless decode/scan passes over its interior.

## The real core: one unified rule model

The matchers are a fixed toolbox. What makes mithril extensible — and gives the user-definable layer — is a
single declarative rule model with two shapes. **Built-in rules are C++ instances of these structs (so they
bind directly to code validators); user rules deserialize into the same structs from a file.** Built-ins and
user rules are the same type; the file is just another source feeding the same engine.

### Path rule
```
PathRule {
  glob        // e.g. "**/*.pem", "var/lib/dpkg/status"
  action      // parse:<parser>   -> dispatch to an M4 format parser
              // flag:<category>  -> record the file as notable (crypto/config/...)
}
```

### Content rule
```
ContentRule {
  anchors[]        // literal strings added to the shared Aho-Corasick automaton (M2)
  window           // bytes to consider around an anchor hit (bounds M3 work; ReDoS-safe)
  extractor        // named M3 step(s): charclass-run | version-regex:<re> | jwt | pem |
                   //   base64-rescan | utf16le-rescan | hex-rescan | crc32:<scheme> | ...
  validators[]     // gate chain: entropy>=X | fp-wordlist | checksum | parse-ok
  category         // "secret" | "component" | "config" | ...
  type             // specific kind, e.g. "github-token", "busybox-version"
  confidence_on_validate  // tier a clean validation earns (see ladder)
}
```

User rules get the safe declarative subset: path globs, content keywords/regex, a category, and by-name
references to built-in validators. Powerful validators (CRC32/JWT/ASN.1) stay code and are referenced by
name; users compose, they do not implement.

## Regex policy: bounded-window, char-class first

- Hot-path validators that fire on every anchor in a large image are **hand-written char-class scanners**
  (fast, already proven in the secrets seed).
- `std::regex` (ECMAScript, stdlib, no new dependency) is allowed **only on the bounded window an anchor
  produces** — never over the whole file. The window bound (typically ≤256 B, capped in the KB range) is
  what makes it safe: worst-case work is bounded and fuzzable. Patterns are compiled once and reused.
- Because regex is confined to windows and named in rules, swapping the implementation later (a tiny
  internal engine, or RE2 if a real need appears) is a localized change.

## Confidence ladder (replaces the old "verification" field)

With no network, "live verification" is gone. Confidence comes from deterministic offline validation:

- **`pattern`** — keyword + shape + entropy matched.
- **`structural`** — the value's own structure parses: a JWT base64-decodes to valid JSON with a real
  `alg` (and we can read `exp` and flag expiry); a PEM/DER key parses and we report algorithm + bit size.
- **`validated`** — an embedded checksum recomputes correctly. Real example: modern GitHub tokens carry a
  CRC32 checksum in the last 6 base62 chars; we recompute (reuse moria's `crc32.hpp`) and confirm/reject.

The tool asserts "this is a well-formed, checksum-valid GitHub token," never "this is a live key." Findings
sort by confidence, so checksum-valid tokens and parseable keys float to the top of a noisy image.

## Considered and rejected as the core

- **Pure regex engine** — slow scanner, no structural validation, ReDoS surface. (Regex kept as a bounded
  extractor only.)
- **YARA / libyara** — great content-matching model, but a C dependency with its own trust surface, and it
  cannot express our structural validators, the SBOM parsers, or the join. We **borrow its model** (its
  `strings` = our anchors, its `condition` = our validator chain) without the dependency; a YARA-rule
  *import* could be an optional user-rule source later.
- **semgrep-style structured/AST config queries** — powerful for config *structure* but dependency-heavy
  and out of scope; revisit only if path+content rules prove insufficient for real config hunting.
- **Network / live verification (TruffleHog)** — removed. Breaks offline/reproducible/air-gappable and, for
  static firmware, adds little over strong offline validation while creating legal/operational risk.

## Build sequence

1. [done] Remove the network/verification path; rework the confidence field into the ladder above.
2. [done] Lock the rule data model (structs) and reimplement the secrets detectors as built-in rules over
   M2/M3.
3. [done] M4 parsers (package DBs `sbom.cpp`; credential stores `credstore.cpp` — shadow/htpasswd with
   crypt-hash classification, weak-hash + empty-password flagging) and the M1 path-rule dispatch
   (`engine.cpp` + `rules_builtin.cpp`).
4. [done] Binary version-string rules (`binver.cpp`, ELF-gated, curated table with co-derived CPE) — the
   firmware value-add. Curated purl/CPE identity map lives in that table; extend as coverage grows.
5. [done] User rule-file loader (`userrules.cpp`, `--rules`) — same structs, safe subset (globs + content
   keyword/regex + category), regex on bounded windows only. See `docs/user-rules.md`.
6. [done] CVE join (`cve.cpp` + `version.cpp` + `cveupdate.cpp`, `--cve` / `--update-db`) — downstream of
   the SBOM, over a local offline mirror, dpkg version comparison, per-match basis. Two paths: **OSV**
   (Debian/Alpine) for package-DB components, and the **NVD/CPE augment** (targeted NVD 2.0 API per curated
   product) for the CPE-bearing binary-version components. Debian-release precision and OSV/NVD CVSS
   reconciliation remain. See `docs/cve-join.md`.
