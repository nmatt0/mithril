// license.hpp — license identification (Phase 4). Fully offline.
//
// Two sources: explicit `SPDX-License-Identifier:` tags in file content (exact,
// machine-readable) and the text of license files (LICENSE / COPYING / NOTICE),
// matched against a built-in set of distinctive per-license markers. Emits
// Findings with category "license", type = the SPDX id/expression. A tag is
// `validated` (declared); a text match is `structural`.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "finding.hpp"

namespace ft {

// Identify SPDX ids from license-file text (may return several; e.g. a COPYING
// that carries both GPL and LGPL). Exposed for testing.
std::vector<std::string> identify_license_text(std::span<const uint8_t> data);

// Scan one file: SPDX tags in its content, plus license-file text identification
// when `relpath`'s basename names a license file. Returns category-"license"
// findings, deduped within the file by license id.
std::vector<Finding> scan_licenses(const std::string& relpath, std::span<const uint8_t> data);

}  // namespace ft
