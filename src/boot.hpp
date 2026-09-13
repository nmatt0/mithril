// boot.hpp — the Boot Security pass.
//
// After moria unpacks an image, this analyzes the boot-level artifacts for
// pentest-relevant intel: U-Boot environment leads (credentials, network config,
// MACs, boot control), device-tree kernel command line, hardware fingerprint,
// and FIT verified-boot posture (signed configs, enforcement, embedded keys).
// Structural facts come from moria; interpretation ("is this a risk") is here.
//
// Findings use category "boot"; `evidence` is prefixed with a severity tag
// ([high]/[medium]/[info]) since the risk of a boot artifact is separate from
// the (always-high) confidence that we parsed it correctly.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "finding.hpp"

namespace ft {

// Analyze one file for boot-security artifacts (U-Boot env, DTB/FIT). Returns the
// leads found; empty if the file is not a recognized boot artifact.
std::vector<Finding> scan_boot(const std::string& path, std::span<const uint8_t> data);

}  // namespace ft
