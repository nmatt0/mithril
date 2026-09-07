// sha256.hpp — a small, dependency-free SHA-256 (FIPS 180-4).
//
// Used to verify the integrity of the prebuilt vulnerability index downloaded by
// `--fetch-db` against a served SHA256SUMS. Owning this in-tree keeps the
// security-critical check from depending on an external `sha256sum` binary (which
// may be absent), matching mithril's stdlib-first posture. Not constant-time and
// not for secret material; it is a content checksum only.
#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace ft {

// Lowercase hex SHA-256 digest of the input bytes.
std::string sha256_hex(std::span<const uint8_t> data);

// Convenience overload for a string of bytes.
std::string sha256_hex(const std::string& data);

}  // namespace ft
