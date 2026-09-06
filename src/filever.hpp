// filever.hpp — SBOM components from versioned library filenames.
//
// Some components encode their exact version in the .so filename rather than a
// readable in-binary banner: the C library above all. `libuClibc-0.9.33.2.so`,
// `libc-2.31.so`, `ld-uClibc-1.0.31.so`. Reading the version off the filename is
// precise (the filename *is* the version) and catches stripped/banner-less libc
// that binver's content scan cannot. Keyed on the basename, no content read.
// This is how Syft/Grype identify libc too. CPE co-derived for the CVE join.
#pragma once

#include <string>
#include <utility>
#include <vector>

#include "component.hpp"

namespace ft {

// Match `relpath`'s basename against the versioned-libc filename table.
std::vector<Component> scan_filename_version(const std::string& relpath);

// The (cpe_vendor, cpe_product) pairs this table can emit, for the NVD updater.
std::vector<std::pair<std::string, std::string>> filever_cpe_products();

}  // namespace ft
