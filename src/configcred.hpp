// configcred.hpp — structure-aware config-credential detector (JSON, v1).
//
// The flat-stream secret engine (rules_builtin.cpp `generic-secret`) is tuned
// for long, high-entropy opaque tokens: it floors the value at 16 chars and
// gates on >=3.5 bits/byte entropy, so a short low-entropy credential assigned
// to a credential-named field (a device PIN, a base64-wrapped passcode) is a
// deliberate false-negative there. Lowering those floors on a flat byte stream
// reintroduces a false-positive storm, because nothing structural separates a
// real `"passwd":"8604"` from `passwd=%s` / `oldpasswddir=...` / `"password":""`.
//
// This pass parses the file as structured config first, so the key name, the
// value, and the key/value relationship are exact. Confidence then comes from a
// strong credential key + a present, non-placeholder value (and a structural
// bump when the value cleanly base64/hex-decodes), never from entropy. The
// parse itself is a strong gate: binary, code, and malformed text never enter.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "finding.hpp"

namespace ft {

// Scan one file for config-credential fields. Returns findings with category
// "config-credential"; empty for anything that is not a small, cleanly-parsing
// structured-config document (v1: JSON). Values are redacted in the result.
std::vector<Finding> scan_config_credentials(const std::string& relpath,
                                             std::span<const uint8_t> data);

}  // namespace ft
