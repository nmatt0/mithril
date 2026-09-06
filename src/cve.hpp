// cve.hpp — the CVE join: SBOM components against a local OSV mirror.
//
// Not a search — a join and a comparator (docs/engine-design.md). It reads the
// normalized OSV index written by `--update-db` (offline), maps each component
// to an OSV ecosystem, and reports the vulns whose affected range contains the
// component's version (dpkg version comparison, version.hpp). Every match records
// its basis per the honesty bar.
//
// First cut: OSV Debian + Alpine ecosystems, which match the dpkg/apk package-DB
// SBOM sources. Binary-version components (pkg:generic + CPE) need the NVD/CPE
// augment (later) and are not matched here.
#pragma once

#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "component.hpp"

namespace ft {

// One event in an OSV affected-range: introduced ('i') / fixed ('f') /
// last_affected ('l'), with the version string ("0" = from the beginning).
struct OsvEvent {
    char type;
    std::string value;
};

struct OsvVuln {
    std::string id;                  // CVE-… (or the OSV id if no CVE alias)
    std::vector<OsvEvent> events;    // in OSV order
    std::string severity;            // CVSS vector, if present
    std::string summary;
    std::string release;             // distro release ("11") when known, else ""
};

// In-memory index: (ecosystem, package) -> vulns.
struct OsvDb {
    // key: "<eco>\x1f<pkg>"
    std::unordered_map<std::string, std::vector<OsvVuln>> index;
    std::string source;      // provenance string from the index file
    std::string generated;   // when the index was built
    size_t vuln_count = 0;

    static std::string key(const std::string& eco, const std::string& pkg) {
        return eco + "\x1f" + pkg;
    }

    // Point lookup by (eco, pkg), matching OsvIndex::lookup so cve_join is
    // generic over both the in-memory OsvDb (tests) and the mmap OsvIndex.
    const std::vector<OsvVuln>& lookup(const std::string& eco, const std::string& pkg) const {
        static const std::vector<OsvVuln> kEmpty;
        auto it = index.find(key(eco, pkg));
        return it == index.end() ? kEmpty : it->second;
    }
};

struct CveMatch {
    std::string cve_id;
    std::string component;       // "name@version"
    std::string component_purl;
    std::string severity;        // CVSS vector, if known
    std::string basis;           // e.g. "exact-range (Debian)"
    std::string summary;
    bool kev = false;            // on the CISA Known-Exploited catalog (annotation only)
    double epss = -1.0;          // EPSS exploit-probability (0..1), -1 if unknown
};

// Canonicalize a vuln id to its CVE form when one is embedded ("DEBIAN-CVE-2021-
// 28831" -> "CVE-2021-28831"); ids with no CVE (e.g. "DSA-1234-1") are unchanged.
std::string canonical_cve(const std::string& id);

// True if `version` falls in the affected range described by `events`.
bool osv_is_affected(const std::string& version, const std::vector<OsvEvent>& events);

// Join components against the index. Generic over the index type: OsvIndex (the
// mmap'd on-disk index, production) and OsvDb (an in-memory map, tests) both
// provide `lookup(eco, pkg)`. `distro_id`/`distro_release` come from the image's
// /etc/os-release: `distro_id` picks the rpm/Ubuntu ecosystem, and
// `distro_release` (e.g. "11", "20.04") tightens matching to that release when
// both the image and the vuln entry name one (empty = release-agnostic).
// Deterministic output.
template <class Index>
std::vector<CveMatch> cve_join(const Index& db, const std::vector<Component>& components,
                               const std::string& distro_id = "",
                               const std::string& distro_release = "");

// Combine + reconcile CVE matches from multiple sources (OSV + NVD): dedup by
// (cve, component), keeping the richest CVSS (v3.1 > v3.0 > v2 > none) and noting
// both bases. Deterministic (sorted) output.
std::vector<CveMatch> reconcile_cves(std::vector<CveMatch> matches);

// ---- exploit annotations (value-add only; never gate a finding) ----
// CISA KEV cve ids from kev.json ({"cves":[...]}); empty if the file is absent.
std::unordered_set<std::string> load_kev(const std::string& path);
// EPSS scores from epss.txt ("CVE,score" per line); empty map if absent.
std::unordered_map<std::string, double> load_epss(const std::string& path);

// ---- NVD / CPE augment ----
// One NVD cpeMatch normalized: an exact `version` (criteria pinned a version and
// carried no bounds) OR a range with inclusive/exclusive start/end bounds (empty
// = unbounded). If all are empty the CVE applies to every version of the product.
struct NvdVuln {
    std::string id;
    std::string cvss;      // CVSS vector, if present
    std::string version;   // exact-version match (else "")
    std::string start_incl, start_excl, end_incl, end_excl;
};

struct NvdDb {
    // key: "<vendor>\x1f<product>"
    std::unordered_map<std::string, std::vector<NvdVuln>> index;
    std::string source;
    std::string generated;
    size_t vuln_count = 0;

    static std::string key(const std::string& vendor, const std::string& product) {
        return vendor + "\x1f" + product;
    }
};

std::optional<NvdDb> load_nvd_db(const std::string& index_path);

// True if `version` is affected by this NVD cpeMatch entry.
bool nvd_is_affected(const std::string& version, const NvdVuln& v);

// Join CPE-bearing components (binary-version) against the NVD db.
std::vector<CveMatch> nvd_join(const NvdDb& db, const std::vector<Component>& components);

}  // namespace ft
