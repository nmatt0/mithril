# Boot-key reference corpus (sources)

Public **keys and certificates only** — never private keys. `tools/gen_bootkeys.py`
fingerprints these and emits `src/bootkeys_corpus.inc`, which is compiled into the
binary; a scan reads no external table and makes no network call. Regenerate after
changing anything here:

    python3 tools/gen_bootkeys.py          # rewrite the .inc
    python3 tools/gen_bootkeys.py --check   # verify it is up to date (run in CI)

## aosp-avb/

AVB public-key blobs (`avbtool extract_public_key`) of the AOSP AVB **test** keys.
A device that signs its vbmeta with one of these has a forgeable verified-boot
chain (the private keys are public).

- Source: AOSP `external/avb/test/data/testkey_rsa{2048,4096,8192}.pem`
  (android.googlesource.com/platform/external/avb, Apache-2.0)
- Fingerprint: SHA-256 of the AVB pubkey blob (what mithril's AVB pass hashes).

## aosp-signing/

AOSP APK/OTA code-signing **test** certificates (X.509). An app or OTA signed with
one of these is trusted with the platform's signature permissions; the private keys
are public.

- Source: AOSP `build/make target/product/security/{testkey,platform,shared,media,networkstack}.x509.pem`
- Fingerprint: SHA-256 of the DER certificate.

## pkfail/

The AMI "DO NOT TRUST - AMI Test PK" Platform Key from PKfail (CVE-class supply-chain
failure): a test PK with a public private key reused as the real PK across many OEMs.

- Source: CERT/CC PKfail advisory repo, `AmiTestPk0{0..3}.p7` (VU#455367)
- Fingerprint: SHA-256 of the X.509 cert extracted from the PKCS#7.
