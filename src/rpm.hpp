// rpm.hpp — SBOM components from an rpm database (M4). Fully offline.
//
// rpm stores each installed package as an RPM *header* blob (magic 8e ad e8 01)
// inside its database, and that blob format is identical whether the backend is
// Berkeley DB (`Packages`), ndb (`Packages.db`), or sqlite (`rpmdb.sqlite`). So
// rather than parse three container formats, we scan the DB file for header
// blobs and read the NAME/VERSION/RELEASE/ARCH tags out of each. Purl is
// pkg:rpm/<name>@<version>-<release>; OSV coverage needs a distro ecosystem
// (Red Hat / openSUSE / …) not yet mirrored, so rpm gives SBOM now and CVE via
// the binary-version path in the meantime.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "component.hpp"

namespace ft {

// Parse RPM header blobs out of a raw rpm database file.
std::vector<Component> parse_rpm_db(std::span<const uint8_t> data, const std::string& origin_path);

// Dispatch on `relpath`: parse it if it names an rpm database, else {}.
std::vector<Component> scan_rpm(const std::string& relpath, std::span<const uint8_t> data);

}  // namespace ft
