// langmanifest.hpp — SBOM components from language package manifests / lockfiles.
//
// After package databases (dpkg/opkg/apk) and binary version strings, the third
// SBOM source: the ecosystem lockfiles an IoT app ships (node.js, python, go,
// rust, php, ruby). These give clean name+version with an ecosystem-native purl,
// and map directly to OSV ecosystems (npm / PyPI / Go / crates.io / Packagist /
// RubyGems) for the CVE join. Lockfiles (exact-pinned) are preferred; a plain
// manifest with version ranges is lower confidence. Fully offline.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "component.hpp"

namespace ft {

// Dispatch on `relpath`'s basename: parse it if it is a manifest/lockfile we
// know (package-lock.json, requirements.txt, PKG-INFO/METADATA, go.mod,
// Cargo.lock, composer.lock, Gemfile.lock), else {}.
std::vector<Component> scan_langmanifest(const std::string& relpath, std::span<const uint8_t> data);

}  // namespace ft
