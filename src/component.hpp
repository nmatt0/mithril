// component.hpp — the SBOM component model (Phase 2).
//
// One format-neutral Component per software package/library found in the tree.
// purl is the primary identity (clean from package DBs and language manifests,
// aligns with the OSV feed); CPE is co-derived where known for the CPE-indexed
// firmware C libraries. The CycloneDX and SPDX emitters are thin adapters over a
// vector<Component>; the Phase 3 CVE join keys on purl (falling back to CPE, then
// name+version). Every component records how it was detected and a confidence,
// per the honesty bar.
#pragma once

#include <cstdint>
#include <string>

namespace ft {

struct Component {
    std::string name;
    std::string version;

    std::string purl;  // primary identity, e.g. "pkg:deb/busybox@1.30.1?arch=armhf"
    std::string cpe;   // co-derived where known (curated firmware set); else empty

    std::string type = "library";  // CycloneDX component type: library/application/os
    std::string arch;
    std::string license;  // declared license (SPDX id-ish) when the source carries it

    // Provenance (honesty bar): how it was detected and from which file.
    std::string source;       // "dpkg" / "opkg" / "apk" / "npm" / "binary-version" / ...
    std::string origin_path;  // file it was found in (relative to the scanned root)

    uint8_t confidence = 0;  // 0-100
    std::string evidence;    // short reason, e.g. "dpkg status: install ok installed"
};

}  // namespace ft
