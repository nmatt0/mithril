// credstore.hpp — M4 parsers for OS credential stores (docs/engine-design.md).
//
// Where the content engine (M2/M3) hunts credential *material* anywhere in a
// file, these parse *known credential files* by structure and extract each
// account's password hash, classify its crypt algorithm, and flag the weak ones
// (descrypt/md5crypt/apr1/sha1) and empty passwords. This is high-signal on
// firmware: a hardcoded root hash or a passwordless account is a finding, and
// naming the algorithm tells the operator whether it is crackable. Fully offline.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "finding.hpp"

namespace ft {

// Parse an /etc/shadow-style file: `user:hash:...`. Emits a Finding per account
// with a real hash (type "password-hash", weak flag in the description) and per
// empty-password account (type "empty-password"). Locked accounts (* / !) skip.
std::vector<Finding> parse_shadow(std::span<const uint8_t> data, const std::string& origin);

// Parse an Apache htpasswd file: `user:hash` (apr1 / bcrypt / SHA1 / crypt).
std::vector<Finding> parse_htpasswd(std::span<const uint8_t> data, const std::string& origin);

// Dispatch on `relpath`: parse it if it is a credential store we know, else {}.
std::vector<Finding> scan_credstores(const std::string& relpath, std::span<const uint8_t> data);

}  // namespace ft
