// sbom.hpp — component discovery for the SBOM pass (Phase 2).
//
// Given one file's bytes and its path in the tree, decide whether it is a
// known component source (a package database or, later, a language manifest or
// a version-bearing binary) and extract Components from it. Phase 2 start covers
// the highest-signal sources: the dpkg/opkg (deb822) and apk installed-package
// databases. Language manifests, rpm, and binary version strings come next.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "component.hpp"

namespace ft {

// Parse a dpkg/opkg deb822 `status` file. `source` is "dpkg" or "opkg" (sets the
// provenance and the purl type). Only installed packages are returned.
std::vector<Component> parse_deb822_status(std::span<const uint8_t> data, const std::string& source,
                                           const std::string& origin_path);

// Parse an apk (Alpine) `installed` database.
std::vector<Component> parse_apk_installed(std::span<const uint8_t> data,
                                           const std::string& origin_path);

// Dispatch on `relpath`: if it names a package DB we know, parse it and return
// its components; otherwise return empty. `relpath` is relative to the scan root.
std::vector<Component> scan_sbom(const std::string& relpath, std::span<const uint8_t> data);

}  // namespace ft
