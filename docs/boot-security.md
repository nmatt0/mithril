# Boot security (`--boot`)

The `boot` pass turns boot-level artifacts into pentest intel. Fully offline and
compiled-in: no network at scan time, no runtime tables. mithril owns the
interpretation ("is this a risk"); the structural extraction is upstream (moria /
UEFITool / chipsec). Artifact families:

- **U-Boot environment** — credentials, weak/default bootloader passwords, network
  and provisioning config, MAC/serial, interruptible-console bootdelay, and the
  kernel command line.
- **Device tree / FIT** — kernel command-line risks, hardware fingerprint, and FIT
  verified-boot posture (signed configs, enforcement, embedded keys).
- **AVB / vbmeta** — verification/hashtree flags, algorithm, rollback index,
  descriptors, and the signing-key fingerprint.
- **x86 UEFI Secure Boot** — the variable posture and the signing certificates
  (below).

Findings use category `boot`; `evidence` is prefixed with a severity tag
(`[high]`/`[medium]`/`[info]`), so the human view orders and colors by risk
independent of parse confidence.

## UEFI Secure Boot

The pass recovers the Secure Boot variables (PK, KEK, db, dbx, SecureBoot,
SetupMode) and reports the posture. It reads three inputs:

1. **A raw BIOS image / firmware volume.** Two variable-store formats are walked:
   - the **EDK2 / OVMF** authenticated variable store (the reference format used by
     virtual firmware), and
   - the **AMI NVAR** store used by most real vendor BIOSes (`NVAR` entries with an
     ASCII name and the variable data inline). Without this, a real vendor BIOS
     yields no Secure Boot posture at all, since its variables are not in the EDK2
     format. The EDK2 walk runs first; the NVAR walk is the fallback.
2. **A standalone `EFI_SIGNATURE_LIST`.** An extracted variable (a `PK`/`KEK`/`db`/
   `dbx` blob from UEFITool or chipsec `uefi decode`) is recognized by its
   signature-type GUID and inventoried directly — so mithril rides the standard
   extract-then-analyze workflow.

### What it reports

- `uefi-secureboot-off` (high) — `SecureBoot=0`.
- `uefi-setup-mode` (high) — Setup Mode / no Platform Key: arbitrary keys can be
  enrolled.
- `uefi-platform-key` (info) — PK enrolled; the certificate is fingerprinted.
- `uefi-secureboot-on` (info) — Secure Boot enabled (or provisioned, when the
  runtime `SecureBoot` value is not stored in a firmware image).
- `uefi-test-platform-key` / `uefi-test-key` (high) — a PK/KEK/db certificate is a
  known test/default key whose private key is public (the PKFAIL class); the
  Secure Boot chain is forgeable. Matched against the compiled-in signing-key
  corpus (see the boot-key corpus).
- `uefi-single-anchor` (medium) — the same certificate is the PK, the only KEK, and
  the only db entry: one key anchors the whole chain (single point of compromise).
- `uefi-dbx` (info) / `uefi-dbx-empty` (medium) — the revocation database is
  **enumerated** (count of X.509 + SHA-256/SHA-1 entries), so an empty/stale dbx is
  distinguished from a populated one by content, not just byte size.
- `uefi-siglist` (info) — a standalone signature list's inventory (per-type entry
  counts).

The signing certificates recovered from PK/KEK/db (including those unwrapped from a
standalone `EFI_SIGNATURE_LIST`) also flow into the key-weakness pass (`--keys`),
so a weak, ROCA, leaked, or factorable UEFI signing key is caught there.

### Out of scope (needs live hardware, not offline firmware)

Boot Guard / BIOS Guard fuse policy (Verified/Measured/enforce, FPF), SPI flash
write protection (`BIOS_CNTL.SMM_BWP`, `FLOCKDN`, protected ranges), and update-tool
signature-gate behavior are runtime/hardware states that a static firmware image
does not contain. Those belong to a live platform tool or binary reverse
engineering, not this pass.

## Testing

`tests/test_boot.py` builds synthetic fixtures: an EDK2 store and an AMI NVAR store
(both wrapped in a minimal firmware volume), standalone `EFI_SIGNATURE_LIST` blobs,
a dbx with a known revocation count, and a PKFAIL test-key match through both store
formats. Parsers are fuzzed via `fuzz/fuzz_secrets` and exercised ASan/UBSan-clean.
