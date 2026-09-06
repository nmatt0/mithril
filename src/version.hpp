// version.hpp — Debian-style version comparison (dpkg's algorithm).
//
// Correctness-critical for the CVE join: whether a component version falls in an
// affected range decides whether a CVE is reported. This implements dpkg's
// version comparison exactly — epoch, upstream, revision, and the `~` rule
// (a tilde sorts before everything, so 1.0~rc1 < 1.0). It also handles Alpine's
// `-rN` revisions well enough (the upstream/revision split matches). OSV
// ECOSYSTEM ranges for Debian/Alpine use this ordering.
#pragma once

#include <string>

namespace ft {

// Returns <0, 0, >0 as a < b, a == b, a > b under dpkg version ordering.
int deb_vercmp(const std::string& a, const std::string& b);

}  // namespace ft
