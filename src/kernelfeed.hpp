// kernelfeed.hpp — the full kernel.org (Linux CNA) CVE feed, for --kernel-cves-all.
//
// The curated table (kernelcve.hpp) is the high-signal default: a hand-picked set
// of widely-exploited kernel bugs, kconfig-gated. It is deliberately partial and
// its ranges reach only as far as they are maintained, so a modern kernel outruns
// it. This module is the opt-in complement: the complete, version-matched set of
// Linux-kernel CVEs published by the kernel.org CNA, joined against the detected
// kernel version with branch-aware precision.
//
// The kernel.org records carry per-stable-branch affected intervals (e.g. the
// 6.6.x branch was affected from 6.6.0 until fixed in 6.6.17), so a stable release
// is matched against its own branch and not a coarse mainline range — a 6.6.110
// kernel is correctly excluded from a bug fixed in 6.6.17 even though the mainline
// range still spans it. Ranges that are precise carry basis "branch-exact"; the
// rare coarse/mainline-only ranges carry "broad-range (verify backport)".
//
// The feed is a separate, optional on-disk asset (dbpath: kernel_feed_path). It is
// built by `--update-db --with-kernel-feed` (from the kernel.org vulns snapshot)
// or fetched by `--fetch-db --with-kernel-feed`; absent by default. The scan is
// offline, like every other pass.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "kernelcve.hpp"  // KernelCveResult

namespace ft {

// One affected version interval [introduced, fixed). `fixed` empty == open end.
struct KfRange {
    std::string introduced;
    std::string fixed;
};

// One CVE from the feed: its branch-precise affected intervals, any coarse/mainline
// intervals (matched only for a mainline kernel), CVSS if the record carried one,
// and a short title.
struct KernelFeedEntry {
    std::string cve;
    std::vector<KfRange> ranges;   // branch-precise (self-contained per stable branch)
    std::vector<KfRange> broad;    // coarse/custom intervals: match, but "verify backport"
    KfRange mainline;              // mainline [introduced, fixed); applied only to a mainline version
    std::string severity;          // CVSS base severity ("HIGH"/...), "" if none
    double score = -1.0;           // CVSS base score, -1 if none
    std::string summary;           // short CVE title
};

// Load the prebuilt feed index (kernel_feed_path). std::nullopt when the file is
// absent or unparseable (the caller then tells the user to fetch/build it).
std::optional<std::vector<KernelFeedEntry>> load_kernel_feed(const std::string& path);

// The match basis of `version` against one entry, or "" when not affected:
// "branch-exact" (a precise per-branch interval) or "broad-range" (a coarse or
// mainline interval — flag it, but the backport state needs confirming).
std::string kernel_feed_basis(const std::string& version, const KernelFeedEntry& e);

// Every feed CVE in range for `version`, as KernelCveResults with source
// "kernel.org" and state Applicable (the feed carries no CONFIG data, so it is not
// kconfig-gated — reason records the basis). Sorted by CVE id for determinism.
std::vector<KernelCveResult> kernel_feed_scan(const std::string& version,
                                              const std::vector<KernelFeedEntry>& feed);

// Reconstruct one entry from a parsed kernel.org CVE-5.0 record's `cna` object.
// Exposed for the index builder (cveupdate) and the unit tests. Returns false when
// the record names no usable Linux affected versions.
struct JsonValue;
bool kernel_feed_entry_from_cna(const JsonValue& cna, const std::string& cve_id,
                                KernelFeedEntry& out);

// Serialize entries to the on-disk index JSON (what load_kernel_feed reads). The
// builder collects entries via kernel_feed_entry_from_cna, then writes this.
std::string write_kernel_feed_index(const std::vector<KernelFeedEntry>& entries,
                                    unsigned long long generated);

}  // namespace ft
