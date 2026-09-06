// kconfig.hpp — extract an embedded kernel .config (CONFIG_IKCONFIG).
//
// A kernel built with CONFIG_IKCONFIG stores its gzip-compressed .config bracketed
// by the markers IKCFG_ST ... IKCFG_ED. Inflating it (inflate.hpp) recovers the
// full build config. This matters twice: it tells an analyst the kernel's
// hardening posture, and — the reason it pairs with kernel-CVE triage — it says
// which subsystems/drivers are actually compiled in, so a CVE in a config that
// the target did not enable can be ruled out.
#pragma once

#include <cstdint>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "finding.hpp"

namespace ft {

// Recover the plaintext kernel .config if the file embeds one (IKCFG_ST + gzip).
std::optional<std::string> extract_kconfig(std::span<const uint8_t> data);

// The set of enabled option names (CONFIG_X where X=y or m) from a .config text.
std::set<std::string> kconfig_enabled_options(const std::string& cfg);

// Build the "kernel-config" notable finding (option count + hardening snapshot)
// from an already-extracted .config text.
Finding kconfig_finding(const std::string& cfg);

// Scan a file for an embedded kernel config; emit a "kernel-config" finding
// (category "config") summarizing the option count and key hardening settings.
std::vector<Finding> scan_kconfig(const std::string& relpath, std::span<const uint8_t> data);

}  // namespace ft
