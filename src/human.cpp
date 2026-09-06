#include "human.hpp"

#include <algorithm>
#include <cstdio>

namespace ft {

namespace {

struct Ansi {
    bool on;
    const char* bold() const { return on ? "\033[1m" : ""; }
    const char* dim() const { return on ? "\033[2m" : ""; }
    const char* yellow() const { return on ? "\033[33m" : ""; }
    const char* cyan() const { return on ? "\033[36m" : ""; }
    const char* green() const { return on ? "\033[32m" : ""; }
    const char* red() const { return on ? "\033[31m" : ""; }
    const char* reset() const { return on ? "\033[0m" : ""; }
};

// Color by confidence tier: validated (checksum) strongest, then structural.
const char* tier_color(const Ansi& a, uint8_t conf) {
    if (conf >= static_cast<uint8_t>(Confidence::Validated)) return a.green();
    if (conf >= static_cast<uint8_t>(Confidence::Structural)) return a.cyan();
    return a.yellow();
}

void pad(std::string& o, const std::string& s, size_t w) {
    o += s;
    for (size_t i = s.size(); i < w; ++i) o += ' ';
}

std::string clip(const std::string& s, size_t w) {
    if (s.size() <= w) return s;
    if (w <= 3) return s.substr(0, w);
    return "..." + s.substr(s.size() - (w - 3));
}

}  // namespace

std::string emit_report_human(const Report& rep, const Passes& passes, const std::string& footer,
                              bool color) {
    Ansi a{color};
    std::string o;

    // ---- secrets ----
    if (passes.secrets) {
        size_t validated = 0;
        for (const auto& h : rep.secrets)
            if (h.finding.confidence >= static_cast<uint8_t>(Confidence::Validated)) ++validated;
        o += a.bold();
        o += std::to_string(rep.secrets.size());
        o += rep.secrets.size() == 1 ? " secret" : " secrets";
        o += a.reset();
        if (validated) o += " (" + std::to_string(validated) + " checksum-validated)";
        o += " in ";
        o += std::to_string(rep.file_count);
        o += rep.file_count == 1 ? " file\n" : " files\n";

        if (!rep.secrets.empty()) {
            size_t wtype = 4, wtier = 4, wloc = 8;
            for (const auto& h : rep.secrets) {
                wtype = std::max(wtype, h.finding.type.size());
                wtier = std::max(wtier, h.finding.confidence_tier.size());
                wloc = std::max(wloc, h.path.size() + std::to_string(h.finding.offset).size() + 1);
            }
            wtype = std::min<size_t>(wtype, 28);
            wloc = std::min<size_t>(wloc, 56);
            o += "\n";
            for (const auto& h : rep.secrets) {
                const Finding& f = h.finding;
                std::string loc = clip(h.path + "@" + std::to_string(f.offset), wloc);
                o += "  ";
                o += a.bold();
                pad(o, clip(f.type, wtype), wtype);
                o += a.reset();
                o += "  ";
                o += tier_color(a, f.confidence);
                pad(o, f.confidence_tier, wtier);
                o += a.reset();
                o += "  ";
                o += a.dim();
                pad(o, loc, wloc);
                o += a.reset();
                o += "  ";
                o += f.label;
                o += "\n";
            }
        } else {
            o += a.green();
            o += "no secrets found";
            o += a.reset();
            o += "\n";
        }
    }

    // ---- notable files (secrets path rules + SBOM kconfig) ----
    if ((passes.secrets || passes.sbom) && !rep.notable.empty()) {
        if (passes.secrets) o += "\n";
        o += a.bold();
        o += std::to_string(rep.notable.size());
        o += rep.notable.size() == 1 ? " notable file" : " notable files";
        o += a.reset();
        o += "\n\n";
        size_t wtype = 4;
        for (const auto& h : rep.notable) wtype = std::max(wtype, h.finding.type.size());
        wtype = std::min<size_t>(wtype, 20);
        for (const auto& h : rep.notable) {
            o += "  ";
            o += a.cyan();
            pad(o, clip(h.finding.type, wtype), wtype);
            o += a.reset();
            o += "  ";
            o += h.path;
            o += "\n";
        }
    }

    // ---- SBOM component table ----
    if (passes.sbom) {
        if (passes.secrets) o += "\n";
        o += a.bold();
        o += std::to_string(rep.components.size());
        o += rep.components.size() == 1 ? " component" : " components";
        o += a.reset();
        o += "\n";
        if (!rep.components.empty()) {
            size_t wname = 4, wver = 7, wsrc = 6;
            for (const auto& c : rep.components) {
                wname = std::max(wname, c.name.size());
                wver = std::max(wver, c.version.size());
                wsrc = std::max(wsrc, c.source.size());
            }
            wname = std::min<size_t>(wname, 30);
            wver = std::min<size_t>(wver, 24);
            o += "\n";
            for (const auto& c : rep.components) {
                o += "  ";
                o += a.bold();
                pad(o, clip(c.name, wname), wname);
                o += a.reset();
                o += "  ";
                pad(o, clip(c.version, wver), wver);
                o += "  ";
                o += a.dim();
                pad(o, c.source, wsrc);
                o += a.reset();
                o += "  ";
                o += c.purl;
                o += "\n";
            }
        }
    }

    // ---- CVE matches ----
    if (passes.cve) {
        if (passes.secrets || passes.sbom) o += "\n";
        o += a.bold();
        o += std::to_string(rep.cves.size());
        o += rep.cves.size() == 1 ? " CVE" : " CVEs";
        o += a.reset();
        o += "\n";
        if (!rep.cves.empty()) {
            size_t wcve = 3, wcomp = 9;
            for (const auto& m : rep.cves) {
                wcve = std::max(wcve, m.cve_id.size());
                wcomp = std::max(wcomp, m.component.size());
            }
            wcomp = std::min<size_t>(wcomp, 32);
            o += "\n";
            for (const auto& m : rep.cves) {
                o += "  ";
                o += a.yellow();
                pad(o, m.cve_id, wcve);
                o += a.reset();
                o += "  ";
                o += a.bold();
                pad(o, clip(m.component, wcomp), wcomp);
                o += a.reset();
                o += "  ";
                o += a.dim();
                o += m.basis;
                o += a.reset();
                if (m.kev) {
                    o += a.red();
                    o += " [KEV]";
                    o += a.reset();
                }
                if (m.epss >= 0.10) {  // only surface a non-trivial exploit probability
                    char b[24];
                    std::snprintf(b, sizeof(b), " epss=%.2f", m.epss);
                    o += b;
                }
                o += "\n";
            }
        }
    }

    // ---- curated kernel CVEs (applicable, then ruled-out) ----
    if (passes.cve && !rep.kernel_cves.empty()) {
        o += "\n";
        size_t app = 0;
        for (const auto& k : rep.kernel_cves)
            if (k.applicable) ++app;
        o += a.bold();
        o += std::to_string(app);
        o += " applicable kernel CVE";
        o += app == 1 ? "" : "s";
        o += a.reset();
        o += " (of " + std::to_string(rep.kernel_cves.size()) + " in range for " +
             rep.kernel_version + ")\n\n";
        size_t wcve = 3;
        for (const auto& k : rep.kernel_cves) wcve = std::max(wcve, k.cve.size());
        for (const auto& k : rep.kernel_cves) {
            if (!k.applicable) continue;
            o += "  ";
            o += a.yellow();
            pad(o, k.cve, wcve);
            o += a.reset();
            o += "  ";
            o += a.bold();
            pad(o, k.impact, 4);
            o += a.reset();
            o += "  " + k.note;
            if (k.kev) {
                o += a.red();
                o += " [KEV]";
                o += a.reset();
            }
            if (k.epss >= 0.10) {
                char b[24];
                std::snprintf(b, sizeof(b), " epss=%.2f", k.epss);
                o += b;
            }
            if (!rep.has_kconfig) {
                o += a.dim();
                o += " [config unknown]";
                o += a.reset();
            }
            o += "\n";
        }
        // ruled-out (only meaningful when we had a config to gate with)
        bool any_ruled = false;
        for (const auto& k : rep.kernel_cves)
            if (!k.applicable) any_ruled = true;
        if (any_ruled) {
            o += "\n";
            o += a.dim();
            o += "  ruled out by kconfig:";
            o += a.reset();
            o += "\n";
            for (const auto& k : rep.kernel_cves) {
                if (k.applicable) continue;
                o += "    ";
                o += a.dim();
                pad(o, k.cve, wcve);
                o += "  " + k.reason;
                o += a.reset();
                o += "\n";
            }
        }
    }

    // ---- licenses (aggregated by id) ----
    if (passes.licenses) {
        if (passes.secrets || passes.sbom || passes.cve) o += "\n";
        std::vector<std::pair<std::string, size_t>> agg;  // id -> count, first-seen order
        for (const auto& h : rep.licenses) {
            auto it = std::find_if(agg.begin(), agg.end(),
                                   [&](const auto& p) { return p.first == h.finding.type; });
            if (it == agg.end()) agg.push_back({h.finding.type, 1});
            else it->second++;
        }
        std::sort(agg.begin(), agg.end(), [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second > b.second;
            return a.first < b.first;
        });
        o += a.bold();
        o += std::to_string(agg.size());
        o += agg.size() == 1 ? " license" : " licenses";
        o += a.reset();
        o += "\n";
        if (!agg.empty()) {
            size_t wid = 7;
            for (const auto& p : agg) wid = std::max(wid, p.first.size());
            wid = std::min<size_t>(wid, 24);
            o += "\n";
            for (const auto& p : agg) {
                o += "  ";
                o += a.cyan();
                pad(o, clip(p.first, wid), wid);
                o += a.reset();
                o += "  ";
                o += a.dim();
                o += "x" + std::to_string(p.second);
                o += a.reset();
                o += "\n";
            }
        }
    }

    // ---- read errors ----
    if (!rep.errors.empty()) {
        o += "\n";
        for (const auto& e : rep.errors) {
            o += "  ";
            o += a.yellow();
            o += "unreadable";
            o += a.reset();
            o += "  " + e.first + "  (" + e.second + ")\n";
        }
    }

    // ---- footer ----
    if (!footer.empty()) {
        o += "\n";
        o += footer;
        if (o.back() != '\n') o += "\n";
    }
    return o;
}

}  // namespace ft
