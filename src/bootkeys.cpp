// bootkeys.cpp — the boot-security reference corpus. See bootkeys.hpp.
#include "bootkeys.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>

namespace ft {

namespace {

// Generic weak/default credentials a bootloader password variable must not hold.
// Not vendor-specific research, just the universally-weak set.
constexpr std::string_view kWeakPasswords[] = {
    "",      "root",     "admin",    "password", "pass",   "toor",   "default",
    "1234",  "12345",    "123456",   "1234567",  "12345678", "0000", "1111",
    "guest", "user",     "system",   "uboot",    "u-boot", "linux",  "vendor",
};

// The known test/default signing keys are compiled in from the vendored public
// sources in data/bootkeys/ via tools/gen_bootkeys.py. They ship in the binary
// (no runtime table / no network); the generator runs only at authoring time so
// the corpus stays reproducible from source. kAvbKeys is keyed by the AVB
// public-key-blob SHA-256[0:32]; kCerts by the X.509 DER SHA-256[0:32].
#include "bootkeys_corpus.inc"

}  // namespace

bool is_weak_password(const std::string& value) {
    std::string v = value;
    std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return std::tolower(c); });
    for (std::string_view w : kWeakPasswords)
        if (v == w) return true;
    return false;
}

const KnownKey* known_signing_key(const std::string& sha256_prefix) {
    for (const auto& k : kAvbKeys)
        if (sha256_prefix == k.fp) return &k;
    return nullptr;
}

const KnownKey* known_cert(const std::string& sha256_prefix) {
    for (const auto& k : kCerts)
        if (sha256_prefix == k.fp) return &k;
    return nullptr;
}

}  // namespace ft
