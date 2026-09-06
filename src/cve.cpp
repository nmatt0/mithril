#include "cve.hpp"

#include <algorithm>
#include <cctype>
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
