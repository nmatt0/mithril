// keycorpus.hpp — the leaked/default public-key reference corpus.
//
// The disclosure-failure half of the key-weakness pass: a curated, compiled-in
// set of public keys whose PRIVATE half is already public — hardcoded SSH host
// and authorized keys shipped in appliances/firmware (rapid7/ssh-badkeys), the
// Vagrant insecure key, and (extensible) RFC/example keys. When a scanned device
// ships one of these, an attacker with the matching public-domain private key can
// log in (authorized key) or impersonate the host / MITM it (host key).
//
// Seeded only from PUBLIC material (the vendored `.pub` files under
// data/keycorpus/); no private key is ever stored. Fingerprints are baked in by
// tools/gen_keycorpus.py (like bootkeys) so the scan makes no network call and
// reads no external table. Two fingerprint namespaces are matched:
//   - fp_ssh:  SHA-256[0:32] of the raw OpenSSH public-key blob (exact-key match)
//   - fp_modn: SHA-256[0:32] of the RSA modulus, big-endian, no leading zeros
//              (cross-container: the same key as a cert or a raw SPKI still hits)
#pragma once

#include <string>

namespace ft {

// A known public key whose private half is public. `ref` names where the private
// key lives (why the match matters); `key_use` is "host" / "authorized" / "" to
// drive the impact wording.
struct KnownLeakedKey {
    const char* fp;       // fp_ssh or fp_modn (first 32 lowercase hex of SHA-256)
    const char* label;    // e.g. "F5 BIG-IP hardcoded SSH host key (RSA)"
    const char* ref;      // source + CVE, e.g. "rapid7/ssh-badkeys; CVE-2012-1493"
    const char* key_use;  // "host" | "authorized" | ""
};

// If `fp` (an fp_ssh or fp_modn, 32 lowercase hex chars) matches a known
// leaked/default key, return its entry; else nullptr.
const KnownLeakedKey* known_leaked_key(const std::string& fp);

// Number of entries in the corpus (for the run footer / metadata).
size_t leaked_key_corpus_size();

}  // namespace ft
