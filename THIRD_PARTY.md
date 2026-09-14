# Third-party data

mithril links **no** third-party libraries (see the README). It does vendor small amounts of **public
reference data** used to build compiled-in fingerprint corpora. None of it is private-key material: only
public keys, public certificates, and fingerprints derived from them are stored, and each corpus is
regenerated from these sources by a script at authoring time (never fetched at scan time).

## Key-weakness corpus — `data/keycorpus/`

Public keys whose private half is public, fingerprinted into `src/keycorpus_corpus.inc` by
`tools/gen_keycorpus.py`. See `docs/key-weakness.md`.

- **rapid7/ssh-badkeys** — `data/keycorpus/ssh-badkeys/{host,authorized}/*.pub` (+ `*.yml` metadata).
  Hardcoded SSH host and authorized keys shipped in appliances and firmware. Only the `.pub` (public)
  halves are vendored; the matching private keys live in the upstream repo.
  License: MIT (Copyright (c) 2015 Rapid7). Full text in `data/keycorpus/ssh-badkeys/LICENSE`.
  Source: <https://github.com/rapid7/ssh-badkeys>
- **HashiCorp Vagrant insecure key** — `data/keycorpus/vagrant/vagrant.pub`. The default "insecure" key
  Vagrant ships as an authorized key; its private half is published in the vagrant repo.
  License: MIT (HashiCorp). Source: <https://github.com/hashicorp/vagrant> (`keys/`).

## Boot-key corpus — `data/bootkeys/`

Public test/default signing keys and certificates, fingerprinted into `src/bootkeys_corpus.inc` by
`tools/gen_bootkeys.py`. See the boot pass.

- **AOSP AVB / APK-OTA signing test keys** — `data/bootkeys/aosp-avb/*.avbpubkey`,
  `data/bootkeys/aosp-signing/*.x509.pem`. Public halves of the AOSP test keys whose private keys ship in
  the Android source tree (`external/avb/test/data`, `build/make/.../security`).
  License: Apache-2.0 (The Android Open Source Project). Source: <https://android.googlesource.com/>
- **PKfail "DO NOT TRUST" AMI Platform Key** — `data/bootkeys/pkfail/AmiTestPk*.p7`. The AMI test Platform
  Key found shipped in production UEFI firmware (CERT/CC VU#455367). Public certificate only.
  Source: CERT/CC PKfail disclosure / Binarly.

All vendored data is public and used here for defensive auditing (detecting weak or leaked keys a vendor
still ships). Fingerprints in the generated `.inc` files are derived from these sources and carry the same
provenance.
