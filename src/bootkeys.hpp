// bootkeys.hpp — the boot-security reference corpus.
//
// Two curated, offline reference sets used by the boot pass:
//   1. weak/default bootloader passwords (generic; matched against U-Boot env
//      password variables).
//   2. known test/default signing-key fingerprints (SHA-256, first 32 hex chars)
//      matched against the AVB / FIT / UEFI-PK keys the scanner fingerprints, to
//      flag a "test/default key shipped in production" (the PKFAIL class).
//
// The signing-key table is seeded only from public sources (AOSP AVB/verified-boot
// test keys, the Binarly PKFAIL "DO NOT TRUST" AMI Platform Key). Until those are
// added it returns no match, so the tool never makes a false "test key" claim.
#pragma once

#include <string>

namespace ft {

// A weak/default password (case-insensitive) an env variable should never carry.
bool is_weak_password(const std::string& value);

// A known test/default signing key: its fingerprint, a short label, and a
// reference to where the (public-domain) PRIVATE key lives. When a device ships
// one of these public keys, the matching private key is publicly available, so
// the signature chain it anchors can be forged — that is why `ref` matters.
struct KnownKey {
    const char* fp;     // first 32 lowercase hex chars of the key's SHA-256
    const char* label;  // e.g. "AOSP AVB test key (RSA-2048)"
    const char* ref;    // where the public-domain private key lives
};

// If `sha256_prefix` (first 32 lowercase hex chars) matches a known test/default
// AVB signing key (fingerprint of the AVB public-key blob), returns its entry.
const KnownKey* known_signing_key(const std::string& sha256_prefix);

// If `sha256_prefix` matches a known test/default X.509 signing certificate
// (AOSP APK/OTA signing certs, PKfail AMI test PK), returns its entry. The
// caller fingerprints the DER certificate (see certid.hpp).
const KnownKey* known_cert(const std::string& sha256_prefix);

}  // namespace ft
