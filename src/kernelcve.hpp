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

#include <cstddef>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace ft {

// Per-CVE gating outcome. Three states, because config knowledge is not binary:
// a subsystem can be known-present, known-absent, or undetermined.
enum class KcveState { Applicable, RuledOut, Unknown };

struct KernelCveResult {
    std::string cve;
    std::string impact;      // "LPE" / "RCE" / ...
    std::string note;        // short description + exploit context
    KcveState state = KcveState::Applicable;
    bool applicable = true;  // == (state == Applicable); kept for existing callers
    std::string reason;      // why applicable/ruled-out/unknown, with the evidence source
    // Where this result came from: "curated" (the built-in high-signal table) or
    // "kernel.org" (the full version-matched feed, only with --kernel-cves-all).
    std::string source = "curated";
    // Value-add annotations (never affect applicability):
    bool kev = false;        // on the CISA Known-Exploited catalog
    double epss = -1.0;      // EPSS exploit-probability (0..1), -1 if unknown
};

// Tri-state config knowledge assembled from every available source: an embedded
// or on-disk .config (authoritative), kallsyms symbols, /lib/modules contents,
// and kernel-image strings. Positive evidence rules a subsystem in; a recovered
// .config or a complete-kallsyms-plus-module-exclusion rules it out; otherwise
// an option is undetermined. See kconfig_infer for how it is populated and read.
struct KernelConfigView {
    std::set<std::string> enabled;             // options proven present (any source)
    std::map<std::string, std::string> evidence;  // option -> source label for the verdict
    std::set<std::string> not_builtin;         // complete kallsyms, builtin symbol absent
    std::set<std::string> modules_present;     // option has a .ko / modules.builtin entry
    bool authoritative = false;   // a real .config was recovered: not-enabled == disabled
    bool kallsyms_complete = false;
    bool modules_seen = false;    // a /lib/modules tree or modules.builtin was present

    bool empty() const {
        return enabled.empty() && not_builtin.empty() && modules_present.empty() &&
               !authoritative;
    }
};

// Match a kernel version against the curated table, gating each entry with the
// tri-state config view (nullptr = no config knowledge at all -> every in-range
// entry is Unknown, "config unknown"). Results include applicable, ruled-out,
// and undetermined entries.
std::vector<KernelCveResult> kernel_cve_scan(const std::string& kernel_version,
                                             const KernelConfigView* view);

// Back-compat convenience: an authoritative enabled-set (nullptr = unknown).
// Equivalent to a KernelConfigView{enabled=*enabled, authoritative=true}.
std::vector<KernelCveResult> kernel_cve_scan(const std::string& kernel_version,
                                             const std::set<std::string>* enabled);

// Number of entries in the curated table. Lets the output report "N of <total>
// curated checks in range" so an empty result reads as "none of the curated set
// applies", not "this kernel has no CVEs".
std::size_t kernel_cve_curated_total();

}  // namespace ft
