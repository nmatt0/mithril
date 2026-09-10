#include "human.hpp"

#include <algorithm>
#include <cstdio>

#include "kconfig_infer.hpp"

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

    // ---- curated kernel CVEs (applicable, undetermined, then ruled-out) ----
    // Printed whenever a kernel version was detected, even with zero in-range
    // curated hits: the curated list is a high-signal set, not an exhaustive one,
    // so a modern kernel that outruns the table must still show a line rather than
    // vanish (which reads as "mithril did not see the kernel").
    if (passes.cve && !rep.kernel_version.empty()) {
        o += "\n";
        o += a.bold();
        o += "Kernel CVEs";
        o += a.reset();
        o += a.dim();
        o += "  (curated high-signal checklist, not a full CVE list)";
        o += a.reset();
        o += "\n\n  ";
        size_t app = 0, unk = 0, ruled = 0;
        for (const auto& k : rep.kernel_cves) {
            if (k.state == KcveState::Applicable) ++app;
            else if (k.state == KcveState::Unknown) ++unk;
            else ++ruled;
        }
        if (rep.kernel_cves.empty()) {
            o += a.dim();
            o += "kernel " + rep.kernel_version + " detected; 0 of " +
                 std::to_string(kernel_cve_curated_total()) +
                 " curated checks in range for this version";
            o += a.reset();
        } else {
            o += a.bold();
            o += std::to_string(app);
            o += a.reset();
            o += " applicable of " + std::to_string(rep.kernel_cves.size()) +
                 " curated check" + (rep.kernel_cves.size() == 1 ? "" : "s") +
                 " in range for " + rep.kernel_version;
            if (unk || ruled) {
                o += a.dim();
                o += "  [" + std::to_string(ruled) + " ruled out, " + std::to_string(unk) +
                     " undetermined]";
                o += a.reset();
            }
        }
        // Config posture: how we learned the config, plus the hardening flags,
        // color-coded green=good / yellow=warn / red=bad / (default)=info.
        const auto& kcv = rep.kcv;
        o += a.dim();
        o += "\n  config: ";
        o += a.reset();
        if (kcv.authoritative) {
            o += rep.kconfig_source == "ikconfig" ? "recovered .config (embedded IKCONFIG)"
                 : rep.kconfig_source.empty()     ? "recovered .config"
                                                  : ("recovered .config (" + rep.kconfig_source + ")");
            o += a.dim();
            o += " (" + std::to_string(kcv.enabled.size()) + " options set)";
            o += a.reset();
        } else if (kcv.kallsyms_complete || kcv.modules_seen || !kcv.enabled.empty()) {
            o += "inferred";
            o += a.dim();
            o += kcv.kallsyms_complete ? " (kallsyms" : " (";
            if (kcv.modules_seen) o += kcv.kallsyms_complete ? " + modules" : "modules";
            o += "; no .config)";
            o += a.reset();
        } else {
            o += a.dim();
            o += "unknown (no config, no kallsyms)";
            o += a.reset();
        }
        o += "\n\n";
        size_t wcve = 3;
        for (const auto& k : rep.kernel_cves) wcve = std::max(wcve, k.cve.size());
        for (const auto& k : rep.kernel_cves) {
            if (k.state != KcveState::Applicable) continue;
            o += "  ";
            o += a.red();  // applicable == exploitable attack surface -> bad
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
            o += "\n";
        }
        // undetermined (in range, but the gating config option is unknown)
        if (unk) {
            o += "\n";
            o += a.dim();
            o += "  undetermined (config signal incomplete):";
            o += a.reset();
            o += "\n";
            for (const auto& k : rep.kernel_cves) {
                if (k.state != KcveState::Unknown) continue;
                o += "    ";
                o += a.dim();
                pad(o, k.cve, wcve);
                o += "  " + k.reason;
                o += a.reset();
                o += "\n";
            }
        }
        // ruled-out, with the evidence that ruled each out
        if (ruled) {
            o += "\n";
            o += a.dim();
            o += "  ruled out by config:";
            o += a.reset();
            o += "\n";
            for (const auto& k : rep.kernel_cves) {
                if (k.state != KcveState::RuledOut) continue;
                o += "    ";
                o += a.green();  // ruled out == surface removed -> good
                pad(o, k.cve, wcve);
                o += a.reset();
                o += a.dim();
                o += "  " + k.reason;
                o += a.reset();
                o += "\n";
            }
        }
        // The curated table is deliberately partial: high-signal, widely-exploited
        // bugs only. Say so, so an empty or short list is never read as exhaustive.
        o += "\n";
        o += a.dim();
        o += "  Curated set of widely-exploited kernel bugs, not every CVE for this version.";
        o += a.reset();
        o += "\n";
    }

    // ---- kernel hardening (its own section; only from a recovered .config) ----
    if ((passes.cve || passes.sbom) && !rep.kconfig_text.empty()) {
        auto items = kernel_hardening(rep.kconfig_text);
        if (!items.empty()) {
            o += "\n";
            o += a.bold();
            o += "Kernel hardening";
            o += a.reset();
            o += a.dim();
            o += rep.kconfig_source == "ikconfig" ? "  (from embedded .config)"
                                                  : "  (from recovered .config)";
            o += a.reset();
            o += "\n\n";
            size_t w = 0;
            for (const auto& it : items) w = std::max(w, std::string(it.name).size());
            for (const auto& it : items) {
                o += "  ";
                pad(o, it.name, w);
                o += "  ";
                const char* label;
                const char* col;
                switch (it.state) {
                    case HardState::On: label = "[enabled]"; col = a.green(); break;
                    case HardState::Off: label = "[disabled]"; col = a.red(); break;
                    default: label = "[not available]"; col = a.dim(); break;
                }
                o += col;
                o += label;
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
            // File-scoped errors carry a path and render as "unreadable <path>";
            // scan-level errors (empty path, e.g. a missing CVE DB) render as a
            // plain "error" line.
            o += "  ";
            o += a.yellow();
            o += e.first.empty() ? "error" : "unreadable";
            o += a.reset();
            if (e.first.empty())
                o += "  (" + e.second + ")\n";
            else
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
