// report.hpp — mithril's scan result model + the file/tree walker.
//
// A Report is what one invocation produces: the findings of every selected pass
// over a file or a recursive tree, plus per-pass counts. Phase 1 fills only
// `secrets`; the SBOM / CVE / license passes add their own finding vectors here
// as they land, keeping the JSON and human layers pass-agnostic.
#pragma once

#include <set>
#include <string>
#include <vector>

#include "component.hpp"
#include "cve.hpp"
#include "finding.hpp"
#include "kernelcve.hpp"
#include "rule.hpp"

namespace ft {

// Which passes to run. Mirrors main.cpp's flags; the walker consults it per file.
struct Passes {
    bool secrets = false;
    bool sbom = false;
    bool cve = false;
    bool licenses = false;
    bool any() const { return secrets || sbom || cve || licenses; }
    void all() { secrets = sbom = cve = licenses = true; }
};

// One finding together with the file it was found in (path relative to the root).
struct Hit {
    std::string path;
    Finding finding;
};

struct Report {
    std::string root;        // the file or directory scanned, as given
    bool is_dir = false;
    size_t file_count = 0;   // regular files walked
    size_t bytes_scanned = 0;

    // Detected from /etc/os-release in the tree (for CVE release precision).
    std::string distro_id;       // e.g. "debian", "ubuntu", "openwrt"
    std::string distro_version;  // VERSION_ID, e.g. "11"

    // Kernel context (for the curated kernel-CVE checklist).
    std::string kernel_version;         // from the linux_kernel component, if any
    bool has_kconfig = false;           // an authoritative .config was recovered
    KernelConfigView kcv;               // merged tri-state config knowledge
    std::string kconfig_text;           // verbatim recovered .config (--dump-kconfig)
    std::string kconfig_source;         // "ikconfig" / "on-disk .config" when recovered

    std::vector<Hit> secrets;          // content findings, category "secret"
    std::vector<Hit> notable;          // path-rule hits (credential/crypto/config files)
    std::vector<Component> components;  // SBOM components (dpkg/opkg/apk/...)
    std::vector<CveMatch> cves;         // SBOM-vs-OSV join results
    std::vector<KernelCveResult> kernel_cves;  // curated checklist (+ feed if --kernel-cves-all)
    bool kernel_cves_full = false;      // --kernel-cves-all: the kernel.org feed was merged in
    std::vector<Hit> licenses;          // license findings (SPDX tags + license files)

    // Files that could not be read (path -> reason), surfaced for honesty.
    std::vector<std::pair<std::string, std::string>> errors;
};

// Walk `root` (a single file or a directory tree) with `nthreads` workers,
// running the selected `passes` over each regular file. Regular files only:
// symlinks and special files are skipped. Deterministic — files are processed in
// sorted-path order and hits are path-ordered regardless of thread completion.
// `extra_content`/`extra_paths` are user-defined rules (userrules.hpp) merged
// with the built-ins for this run.
Report scan_path(const std::string& root, const Passes& passes, unsigned nthreads,
                 const std::vector<ContentRule>& extra_content = {},
                 const std::vector<PathRule>& extra_paths = {});

}  // namespace ft
