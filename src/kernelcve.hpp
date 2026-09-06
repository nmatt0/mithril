// kernelcve.hpp — curated high-value Linux-kernel CVE checklist, version- and
// kconfig-gated.
//
// The kernel has thousands of CVEs per version; a version-only match is noise.
// This is a hand-curated table of the kernel bugs that are actually worth an
// attacker's time — reliable LPE/RCE with public exploitation — each with the
// version range it affects and the CONFIG option(s) its subsystem needs. Given
// the target's kernel version and (when we extracted it) its .config, we report
// only the ones whose subsystem is compiled in, and list the rest as ruled out
// with the reason. This is the *deciding* layer; KEV/EPSS are value-add
// annotations layered on top, never gates (KEV in particular skews to
// enterprise IT and misses IoT kernel LPEs).
//
// The table is curated and best-effort: version boundaries are the mainline fix
// (distro/vendor backports vary — verify), so a match is "likely affected,
// confirm the backport", which is exactly the triage an operator wants.
#pragma once

#include <set>
#include <string>
#include <vector>

namespace ft {

struct KernelCveResult {
    std::string cve;
    std::string impact;      // "LPE" / "RCE" / ...
    std::string note;        // short description + exploit context
    bool applicable = true;  // false = ruled out by kconfig
    std::string reason;      // why applicable/ruled-out ("config unknown", "requires CONFIG_X", ...)
    // Value-add annotations (never affect applicability):
    bool kev = false;        // on the CISA Known-Exploited catalog
    double epss = -1.0;      // EPSS exploit-probability (0..1), -1 if unknown
};

// Match a kernel version against the curated table. `enabled` is the set of
// enabled CONFIG_* options from the target's .config, or nullptr when no config
// was recovered (then nothing is ruled out — findings are marked "config
// unknown"). Results include both applicable and ruled-out entries.
std::vector<KernelCveResult> kernel_cve_scan(const std::string& kernel_version,
                                             const std::set<std::string>* enabled);

}  // namespace ft
