// keys.hpp — the Key Weakness pass.
//
// Recovers the public keys in a file (pubkey.hpp) and reports any whose private
// half is obtainable: a leaked/default/hardcoded key whose private half is public
// (keycorpus.hpp), an RSA modulus with the ROCA fingerprint (keyweak.hpp), or a
// structurally weak key (undersized modulus, broken exponent). This is the
// complement to the secrets pass: secrets finds private keys that are *present*;
// this pass finds public keys whose private half is *recoverable*.
//
// Findings use category "keys"; `evidence` is prefixed with a severity tag
// ([high]/[medium]/[info]) like the boot pass, so the human renderer orders and
// colors them by risk independent of parse confidence.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "finding.hpp"

namespace ft {

// One RSA public key recovered from a file, kept for the cross-file batch-GCD
// shared-prime check (which needs every modulus in the tree, not one file's).
struct RsaKeyInfo {
    size_t offset = 0;
    std::vector<uint8_t> n;  // modulus, big-endian, minimal
    uint64_t e = 0;
    size_t bits = 0;
};

// Analyze one file for public-key weaknesses. Returns one finding per (key, issue);
// keys with no issue are not reported (kept high-signal). Empty if no keys or no
// issues found. If `out_rsa` is non-null, every recovered RSA public key is
// appended to it (for the batch-GCD pass run once over the whole tree).
std::vector<Finding> scan_keys(const std::string& path, std::span<const uint8_t> data,
                               std::vector<RsaKeyInfo>* out_rsa = nullptr);

}  // namespace ft
