#include "cve.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <string_view>

#include "io_util.hpp"
#include "jsonparse.hpp"
#include "osvindex.hpp"
#include "version.hpp"

namespace ft {

// Canonicalize a vuln id to its CVE form when one is embedded, so OSV's
// per-distro ids ("DEBIAN-CVE-2021-28831") report as "CVE-2021-28831". Ids with
// no CVE (e.g. "DSA-1234-1") are left as-is. (Declared in cve.hpp.)
std::string canonical_cve(const std::string& id) {
    size_t p = id.find("CVE-");
    if (p == std::string::npos) return id;
    size_t q = p + 4;
    auto digits = [&](size_t& i) {
        size_t start = i;
        while (i < id.size() && std::isdigit(static_cast<unsigned char>(id[i]))) ++i;
        return i > start;
    };
    size_t i = q;
    if (!digits(i)) return id;
    if (i >= id.size() || id[i] != '-') return id;
    ++i;
    if (!digits(i)) return id;
    return id.substr(p, i - p);
}

namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// The OSV ecosystem for an rpm component, from the image's os-release id.
std::string rpm_eco(const std::string& distro_id) {
    std::string id = lower(distro_id);
    if (id == "rhel" || id == "redhat" || id == "red hat" || id == "centos" || id == "fedora")
        return "Red Hat";
    if (id == "rocky") return "Rocky Linux";
    if (id == "almalinux" || id == "alma") return "AlmaLinux";
    if (id.rfind("opensuse", 0) == 0) return "openSUSE";
    if (id == "sles" || id == "sled" || id == "suse" || id.rfind("sle", 0) == 0) return "SUSE";
    return {};  // unknown rpm distro -> no OSV ecosystem (binary-version still covers C libs)
}

// Map an SBOM component source to the OSV ecosystem we index it under.
std::string source_to_eco(const std::string& source, const std::string& distro_id) {
    // dpkg is Debian by default, Ubuntu when the image's os-release id says so
    // (Ubuntu forks Debian and patches on its own schedule / version scheme).
    if (source == "dpkg") return lower(distro_id) == "ubuntu" ? "Ubuntu" : "Debian";
    if (source == "apk") return "Alpine";
    if (source == "rpm") return rpm_eco(distro_id);
    // Language ecosystems (from langmanifest).
    if (source == "npm") return "npm";
    if (source == "pypi") return "PyPI";
    if (source == "golang") return "Go";
    if (source == "cargo") return "crates.io";
    if (source == "composer") return "Packagist";
    if (source == "gem") return "RubyGems";
    return {};  // opkg / binary-version: no OSV ecosystem (binary-version -> NVD/CPE)
}

}  // namespace

bool osv_is_affected(const std::string& version, const std::vector<OsvEvent>& events) {
    bool affected = false;
    for (const auto& e : events) {
        if (e.type == 'i') {
            if (e.value == "0" || deb_vercmp(version, e.value) >= 0) affected = true;
        } else if (e.type == 'f') {
            if (deb_vercmp(version, e.value) >= 0) affected = false;
        } else if (e.type == 'l') {
            if (deb_vercmp(version, e.value) > 0) affected = false;
        }
    }
    return affected;
}


template <class Index>
std::vector<CveMatch> cve_join(const Index& db, const std::vector<Component>& components,
                               const std::string& distro_id, const std::string& distro_release) {
    std::vector<CveMatch> out;
    for (const auto& c : components) {
        std::string eco = source_to_eco(c.source, distro_id);
        if (eco.empty() || c.name.empty() || c.version.empty()) continue;
        // OsvDb::lookup returns a const ref; OsvIndex::lookup a temporary vector.
        // Binding to a const ref keeps the temporary alive for the loop.
        const auto& vulns = db.lookup(eco, c.name);
        for (const auto& v : vulns) {
            // Release precision: if both the image and the vuln name a release,
            // require them to agree; otherwise match release-agnostically.
            bool precise = !distro_release.empty() && !v.release.empty();
            if (precise && v.release != distro_release) continue;
            if (!osv_is_affected(c.version, v.events)) continue;
            CveMatch m;
            m.cve_id = v.id;
            m.component = c.name + "@" + c.version;
            m.component_purl = c.purl;
            m.severity = v.severity;
            m.basis = precise ? "exact-range (" + eco + ":" + v.release + ")"
                              : "exact-range (" + eco + ")";
            m.summary = v.summary;
            out.push_back(std::move(m));
        }
    }
    // Deterministic order + dedup identical (cve, component).
    std::sort(out.begin(), out.end(), [](const CveMatch& a, const CveMatch& b) {
        if (a.component != b.component) return a.component < b.component;
        return a.cve_id < b.cve_id;
    });
    out.erase(std::unique(out.begin(), out.end(),
                          [](const CveMatch& a, const CveMatch& b) {
                              return a.cve_id == b.cve_id && a.component == b.component;
                          }),
              out.end());
    return out;
}

// Explicit instantiations: the mmap index (production) and the in-memory map (tests).
template std::vector<CveMatch> cve_join<OsvIndex>(const OsvIndex&, const std::vector<Component>&,
                                                  const std::string&, const std::string&);
template std::vector<CveMatch> cve_join<OsvDb>(const OsvDb&, const std::vector<Component>&,
                                               const std::string&, const std::string&);

namespace {
// Richness of a CVSS vector for reconciliation: 3.1 > 3.0 > 2.0 > none.
int cvss_rank(const std::string& v) {
    if (v.rfind("CVSS:3.1", 0) == 0) return 4;
    if (v.rfind("CVSS:3.0", 0) == 0) return 3;
    if (!v.empty()) return 2;  // a v2 vector ("AV:N/AC:L/...") or other
    return 0;
}
}  // namespace

// One base-metric value char from any CVSS vector, v2 ("AV:N/AC:L/Au:N/...") or
// v3.x ("CVSS:3.1/AV:N/..."); the leading "CVSS:3.x" token is skipped naturally
// since we never query the "CVSS" key. Returns 0 if the metric is absent.
static char cvss_metric(const std::string& v, std::string_view key) {
    size_t i = 0;
    while (i < v.size()) {
        size_t slash = v.find('/', i);
        std::string_view tok(v.data() + i, (slash == std::string::npos ? v.size() : slash) - i);
        size_t colon = tok.find(':');
        if (colon != std::string_view::npos && colon + 1 < tok.size() && tok.substr(0, colon) == key)
            return tok[colon + 1];
        if (slash == std::string::npos) break;
        i = slash + 1;
    }
    return 0;
}

// CVSS v3.0/v3.1 base score (spec arithmetic). v3.0 uses the same weights and an
// equivalent roundup for our purposes. Returns -1.0 on an incomplete vector.
static double cvss3_base_score(const std::string& vector) {
    char AV = cvss_metric(vector, "AV"), AC = cvss_metric(vector, "AC");
    char PR = cvss_metric(vector, "PR"), UI = cvss_metric(vector, "UI");
    char S = cvss_metric(vector, "S"), C = cvss_metric(vector, "C");
    char I = cvss_metric(vector, "I"), A = cvss_metric(vector, "A");
    if (!AV || !AC || !PR || !UI || !S || !C || !I || !A) return -1.0;
    const bool changed = (S == 'C');
    double av = AV == 'N' ? 0.85 : AV == 'A' ? 0.62 : AV == 'L' ? 0.55 : AV == 'P' ? 0.20 : -1;
    double ac = AC == 'L' ? 0.77 : AC == 'H' ? 0.44 : -1.0;
    double pr = PR == 'N' ? 0.85
                : PR == 'L' ? (changed ? 0.68 : 0.62)
                : PR == 'H' ? (changed ? 0.50 : 0.27) : -1.0;
    double ui = UI == 'N' ? 0.85 : UI == 'R' ? 0.62 : -1.0;
    auto cia = [](char m) -> double {
        switch (m) { case 'H': return 0.56; case 'L': return 0.22; case 'N': return 0.0;
                     default: return -1; }
    };
    double c = cia(C), ii = cia(I), a = cia(A);
    if (av < 0 || ac < 0 || pr < 0 || ui < 0 || c < 0 || ii < 0 || a < 0) return -1.0;
    double iss = 1.0 - (1.0 - c) * (1.0 - ii) * (1.0 - a);
    double impact = changed ? 7.52 * (iss - 0.029) - 3.25 * std::pow(iss - 0.02, 15)
                            : 6.42 * iss;
    if (impact <= 0.0) return 0.0;
    double expl = 8.22 * av * ac * pr * ui;
    double raw = changed ? 1.08 * (impact + expl) : (impact + expl);
    if (raw > 10.0) raw = 10.0;
    return std::ceil(raw * 10.0) / 10.0;  // CVSS 3.1 Roundup to one decimal
}

// CVSS v2 base score (spec arithmetic). Old CVEs carry only a v2 vector, and the
// default human view applies a hard High/Critical (>= 7.0) floor, so scoring v2
// too keeps genuinely severe pre-2016 CVEs visible instead of dropping them for
// want of a v3 vector. Returns -1.0 on an incomplete vector.
static double cvss2_base_score(const std::string& vector) {
    char AV = cvss_metric(vector, "AV"), AC = cvss_metric(vector, "AC");
    char Au = cvss_metric(vector, "Au"), C = cvss_metric(vector, "C");
    char I = cvss_metric(vector, "I"), A = cvss_metric(vector, "A");
    double av = AV == 'N' ? 1.0 : AV == 'A' ? 0.646 : AV == 'L' ? 0.395 : -1;
    double ac = AC == 'L' ? 0.71 : AC == 'M' ? 0.61 : AC == 'H' ? 0.35 : -1;
    double au = Au == 'N' ? 0.704 : Au == 'S' ? 0.56 : Au == 'M' ? 0.45 : -1;
    auto imp = [](char m) -> double {
        switch (m) { case 'C': return 0.660; case 'P': return 0.275; case 'N': return 0.0;
                     default: return -1; }
    };
    double c = imp(C), i = imp(I), a = imp(A);
    if (av < 0 || ac < 0 || au < 0 || c < 0 || i < 0 || a < 0) return -1.0;
    double impact = 10.41 * (1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a));
    double expl = 20.0 * av * ac * au;
    double f = impact == 0.0 ? 0.0 : 1.176;
    double bs = ((0.6 * impact) + (0.4 * expl) - 1.5) * f;
    if (bs < 0.0) bs = 0.0;
    return std::round(bs * 10.0) / 10.0;  // v2 rounds to one decimal
}

// CVSS base score from a vector string, v2 or v3.x. We mirror only the vector
// (not the number), so recompute it deterministically. -1.0 if unparseable.
double cvss_base_score(const std::string& vector) {
    if (vector.rfind("CVSS:3.", 0) == 0) return cvss3_base_score(vector);
    if (cvss_metric(vector, "Au")) return cvss2_base_score(vector);  // v2 marker
    return -1.0;
}

// The default human view keeps only foothold-worthy component CVEs (see cve.hpp).
// KEV is unconditional (exploited in the wild). Otherwise a hard High/Critical
// floor applies: Critical (>= 9.0) always shows; below that a CVE must be at least
// High (>= 7.0), have EPSS traction, be low-complexity, and either carry a real
// confidentiality/integrity impact or be a *remote* DoS that is actually trending
// (a higher EPSS bar). Local DoS is dropped entirely. The floor is computed for v2
// and v3 alike so old CVEs are judged, not hidden by default for lack of a v3
// vector.
bool cve_is_high_signal(const CveMatch& m) {
    if (m.kev) return true;                                       // exploited in the wild
    double score = cvss_base_score(m.severity);
    if (score >= kHighSignalCvss) return true;                   // Critical, any shape
    if (score < kHighFloorCvss) return false;                    // hard floor: High/Critical only
    if (m.epss < kHighSignalEpss) return false;                  // High needs EPSS traction
    if (cvss_metric(m.severity, "AC") != 'L') return false;      // drop high-complexity crypto
    char c = cvss_metric(m.severity, "C"), i = cvss_metric(m.severity, "I");
    bool has_ci = (c && c != 'N') || (i && i != 'N');            // v2 P/C or v3 L/H
    if (has_ci) return true;                                     // real confidentiality/integrity impact
    // Availability-only == DoS. Keep only a REMOTE (AV:N) DoS that is trending;
    // local/adjacent/physical DoS is not worth a default row.
    if (cvss_metric(m.severity, "AV") != 'N') return false;
    return m.epss >= kDosEpss;
}

std::unordered_set<std::string> load_kev(const std::string& path) {
    std::unordered_set<std::string> out;
    auto rf = read_file(path);
    if (!rf) return out;
    std::string text = std::move(*rf);
    auto doc = json_parse(text);
    if (!doc || !doc->is_object()) return out;
    if (const JsonValue* c = doc->find("cves"); c && c->is_array())
        for (const JsonValue& v : c->arr)
            if (v.is_string()) out.insert(v.str);
    return out;
}

std::unordered_map<std::string, double> load_epss(const std::string& path) {
    std::unordered_map<std::string, double> out;
    auto rf = read_file(path);
    if (!rf) return out;
    std::string text = std::move(*rf);
    size_t start = 0;
    while (start < text.size()) {
        size_t nl = text.find('\n', start);
        std::string_view line(text.data() + start,
                              (nl == std::string::npos ? text.size() : nl) - start);
        start = (nl == std::string::npos) ? text.size() : nl + 1;
        size_t comma = line.find(',');
        if (comma == std::string_view::npos) continue;
        std::string cve(line.substr(0, comma));
        if (cve.rfind("CVE-", 0) != 0) continue;
        try {
            out[cve] = std::stod(std::string(line.substr(comma + 1)));
        } catch (...) {
        }
    }
    return out;
}

std::vector<CveMatch> reconcile_cves(std::vector<CveMatch> matches) {
    std::sort(matches.begin(), matches.end(), [](const CveMatch& a, const CveMatch& b) {
        if (a.component != b.component) return a.component < b.component;
        return a.cve_id < b.cve_id;
    });
    std::vector<CveMatch> out;
    for (auto& m : matches) {
        if (!out.empty() && out.back().cve_id == m.cve_id && out.back().component == m.component) {
            CveMatch& kept = out.back();
            // Keep the richer CVSS; note both bases when they differ.
            if (cvss_rank(m.severity) > cvss_rank(kept.severity)) kept.severity = m.severity;
            if (kept.basis.find(m.basis) == std::string::npos) kept.basis += " + " + m.basis;
            if (kept.summary.empty()) kept.summary = m.summary;
        } else {
            out.push_back(std::move(m));
        }
    }
    return out;
}

// ---- NVD / CPE augment ----

namespace {

// Split a CPE 2.3 string into fields. Returns vendor(3), product(4), version(5).
struct CpeParts {
    std::string vendor, product, version;
    bool ok = false;
};
CpeParts parse_cpe(const std::string& cpe) {
    CpeParts p;
    std::vector<std::string> f;
    size_t start = 0;
    while (start <= cpe.size()) {
        size_t colon = cpe.find(':', start);
        f.push_back(cpe.substr(start, colon == std::string::npos ? std::string::npos : colon - start));
        if (colon == std::string::npos) break;
        start = colon + 1;
    }
    if (f.size() < 6 || f[0] != "cpe") return p;
    p.vendor = f[3];
    p.product = f[4];
    p.version = f[5];
    p.ok = true;
    return p;
}

}  // namespace

bool nvd_is_affected(const std::string& version, const NvdVuln& v) {
    if (!v.version.empty()) return deb_vercmp(version, v.version) == 0;  // exact
    if (!v.start_incl.empty() && deb_vercmp(version, v.start_incl) < 0) return false;
    if (!v.start_excl.empty() && deb_vercmp(version, v.start_excl) <= 0) return false;
    if (!v.end_incl.empty() && deb_vercmp(version, v.end_incl) > 0) return false;
    if (!v.end_excl.empty() && deb_vercmp(version, v.end_excl) >= 0) return false;
    return true;  // no bounds and no exact version -> all versions of the product
}

std::optional<NvdDb> load_nvd_db(const std::string& index_path) {
    auto rf = read_file(index_path);
    if (!rf) return std::nullopt;
    std::string text = std::move(*rf);
    auto doc = json_parse(text);
    if (!doc || !doc->is_object()) return std::nullopt;

    NvdDb db;
    db.source = doc->get_str("source");
    db.generated = doc->get_str("generated");
    const JsonValue* vulns = doc->find("vulns");
    if (!vulns || !vulns->is_array()) return db;

    for (const JsonValue& v : vulns->arr) {
        std::string vendor = v.get_str("vendor");
        std::string product = v.get_str("product");
        if (vendor.empty() || product.empty()) continue;
        NvdVuln nv;
        nv.id = canonical_cve(v.get_str("id"));
        nv.cvss = v.get_str("cvss");
        nv.version = v.get_str("ver");
        nv.start_incl = v.get_str("si");
        nv.start_excl = v.get_str("se");
        nv.end_incl = v.get_str("ei");
        nv.end_excl = v.get_str("ee");
        db.index[NvdDb::key(vendor, product)].push_back(std::move(nv));
        db.vuln_count++;
    }
    return db;
}

std::vector<CveMatch> nvd_join(const NvdDb& db, const std::vector<Component>& components) {
    std::vector<CveMatch> out;
    for (const auto& c : components) {
        if (c.cpe.empty() || c.version.empty()) continue;  // CPE-bearing only
        CpeParts p = parse_cpe(c.cpe);
        if (!p.ok || p.vendor.empty() || p.product.empty()) continue;
        auto it = db.index.find(NvdDb::key(p.vendor, p.product));
        if (it == db.index.end()) continue;
        for (const auto& v : it->second) {
            if (!nvd_is_affected(c.version, v)) continue;
            CveMatch m;
            m.cve_id = v.id;
            m.component = c.name + "@" + c.version;
            m.component_purl = c.purl;
            m.severity = v.cvss;
            m.basis = "nvd-cpe-range (" + p.vendor + ":" + p.product + ")";
            out.push_back(std::move(m));
        }
    }
    std::sort(out.begin(), out.end(), [](const CveMatch& a, const CveMatch& b) {
        if (a.component != b.component) return a.component < b.component;
        return a.cve_id < b.cve_id;
    });
    out.erase(std::unique(out.begin(), out.end(),
                          [](const CveMatch& a, const CveMatch& b) {
                              return a.cve_id == b.cve_id && a.component == b.component;
                          }),
              out.end());
    return out;
}

}  // namespace ft
