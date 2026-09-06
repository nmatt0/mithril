// validators.hpp — the M3 token-level validator/extractor library.
//
// Small building blocks that rule matchers (rules_builtin.cpp) compose: char
// classes, bounded runs, redaction, false-positive filtering, base64 decoding,
// and the offline structural/checksum validators that anchor the confidence
// ladder (GitHub token CRC32, JWT decode, PEM key type). All operate on a
// bounded window around an anchor — never over the whole file.
#pragma once

#include <cctype>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "reader.hpp"

namespace ft {

// ---- character-class predicates ----
inline bool c_alnum(uint8_t c) { return std::isalnum(c); }
inline bool c_alnum_us(uint8_t c) { return std::isalnum(c) || c == '_'; }
inline bool c_base32u(uint8_t c) { return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'); }
inline bool c_base64url(uint8_t c) { return std::isalnum(c) || c == '-' || c == '_'; }
inline bool c_base64url_dot(uint8_t c) { return c_base64url(c) || c == '.'; }
inline bool c_secretval(uint8_t c) {
    return std::isalnum(c) || c == '-' || c == '_' || c == '+' || c == '/' || c == '.' ||
           c == '=' || c == '~' || c == '@' || c == '!' || c == '#' || c == '%' || c == '^' ||
           c == '&' || c == '*';
}
inline bool is_b64_char(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' ||
           c == '/';
}

// Length of the run of `pred` chars at `off`, capped at `max`. Bounds-checked.
size_t run(const Reader& r, size_t off, size_t max, bool (*pred)(uint8_t));

// Copy `len` bytes at `off` into a std::string (bounds-checked; short on overrun).
std::string token_str(const Reader& r, size_t off, size_t len);

// first4...last4 (or first3... for short tokens). Used for display labels.
std::string redact(const std::string& tok);

// Semantic placeholder/example words (case-insensitive substring). Not digit/hex
// runs, which occur inside real tokens.
bool is_false_positive(const std::string& tok);

// Shannon entropy (bits/byte) of the token's bytes.
double token_entropy(const std::string& tok);

// Standard base64 and base64url decoders (stop at first invalid/`=`).
std::vector<uint8_t> base64_decode(std::span<const uint8_t> in);
std::vector<uint8_t> base64url_decode(std::span<const uint8_t> in);

// ---- offline structural / checksum validators ----

// GitHub classic token checksum: token = prefix + 30 base62 body + 6 base62
// CRC32 checksum. Returns true if the trailing 6 chars equal base62(crc32(body)).
// A mismatch is NOT proof it is fake — it only means "do not upgrade to
// validated". `prefix_len` is 4 for "ghp_" etc.
// NOTE: the base62 alphabet follows GitHub's published scheme; verify against a
// real token before relying on `validated` for GitHub in the field.
bool github_token_crc_ok(const std::string& token, size_t prefix_len);
std::string base62_crc32_6(std::span<const uint8_t> body);  // exposed for tests

struct JwtInfo {
    bool ok = false;         // three base64url parts and a decodable JSON header/payload
    std::string alg;         // "alg" from the header, when present
    long long exp = 0;       // "exp" claim (epoch seconds), 0 if absent
    bool expired = false;    // exp present and in the past (relative to `now_epoch`)
};

// Inspect a JWT string (header.payload[.signature]) offline: decode header +
// payload, read alg and exp. `now_epoch` gates the expired flag (pass 0 to skip).
JwtInfo jwt_inspect(const std::string& token, long long now_epoch);

// The key type named in a PEM header line "-----BEGIN <TYPE> PRIVATE KEY-----"
// (e.g. "RSA", "EC", "OPENSSH", "DSA", "PGP", or "" for a bare PRIVATE KEY).
std::string pem_key_type(const std::string& header_line);

}  // namespace ft
