#include "json.hpp"

#include <algorithm>
#include <cstdio>

#include "kconfig_infer.hpp"
#include "strutil.hpp"

namespace ft {

// Output JSON schema version. Bump on any breaking change to field names/shapes.
constexpr int MT_SCHEMA_VERSION = 1;

namespace {

void kv_str(std::string& o, const char* key, const std::string& val, bool& first) {
    if (!first) o += ",";
    first = false;
    o += "\"";
    o += key;
    o += "\":\"";
    json_escape(o, val);
    o += "\"";
}

void kv_num(std::string& o, const char* key, unsigned long long val, bool& first) {
    if (!first) o += ",";
    first = false;
    o += "\"";
    o += key;
    o += "\":";
    o += std::to_string(val);
}

void kv_bool(std::string& o, const char* key, bool val, bool& first) {
    if (!first) o += ",";
    first = false;
    o += "\"";
    o += key;
    o += "\":";
    o += val ? "true" : "false";
}

// Emit one Hit as a JSON object: the file path plus its finding's fields.
void emit_hit(std::string& o, const Hit& h) {
    o += "{";
    bool first = true;
    kv_str(o, "path", h.path, first);
    kv_num(o, "offset", h.finding.offset, first);
    kv_num(o, "size", h.finding.size, first);
    kv_str(o, "type", h.finding.type, first);
    kv_str(o, "category", h.finding.category, first);
    kv_num(o, "confidence", h.finding.confidence, first);
    kv_str(o, "confidence_tier", h.finding.confidence_tier, first);
    if (!h.finding.label.empty()) kv_str(o, "label", h.finding.label, first);
    if (!h.finding.version.empty()) kv_str(o, "version", h.finding.version, first);
    kv_str(o, "evidence", h.finding.evidence, first);
    kv_str(o, "description", h.finding.description, first);
    o += "}";
}

void emit_component(std::string& o, const Component& c) {
    o += "{";
    bool first = true;
    kv_str(o, "name", c.name, first);
    kv_str(o, "version", c.version, first);
    if (!c.purl.empty()) kv_str(o, "purl", c.purl, first);
    if (!c.cpe.empty()) kv_str(o, "cpe", c.cpe, first);
    kv_str(o, "type", c.type, first);
    if (!c.arch.empty()) kv_str(o, "arch", c.arch, first);
    if (!c.license.empty()) kv_str(o, "license", c.license, first);
    kv_str(o, "source", c.source, first);
    kv_str(o, "origin_path", c.origin_path, first);
    kv_num(o, "confidence", c.confidence, first);
    kv_str(o, "evidence", c.evidence, first);
    o += "}";
}

void emit_cve(std::string& o, const CveMatch& m) {
    o += "{";
    bool first = true;
    kv_str(o, "cve", m.cve_id, first);
    kv_str(o, "component", m.component, first);
    if (!m.component_purl.empty()) kv_str(o, "purl", m.component_purl, first);
    if (!m.severity.empty()) kv_str(o, "severity", m.severity, first);
    kv_str(o, "basis", m.basis, first);
    if (!m.summary.empty()) kv_str(o, "summary", m.summary, first);
    if (m.kev) kv_bool(o, "kev", true, first);
    if (m.epss >= 0) {
        char b[16];
        std::snprintf(b, sizeof(b), "%.4f", m.epss);
        if (!first) o += ",";
        first = false;
        o += "\"epss\":";
        o += b;
    }
    o += "}";
}

std::string make_summary(const Report& rep, const Passes& passes) {
    std::string s;
    if (passes.secrets) {
        size_t validated = 0;
        for (const auto& h : rep.secrets)
            if (h.finding.confidence >= static_cast<uint8_t>(Confidence::Validated)) ++validated;
        s += std::to_string(rep.secrets.size()) + " secret";
        if (rep.secrets.size() != 1) s += "s";
        if (validated) s += " (" + std::to_string(validated) + " checksum-validated)";
        if (!rep.notable.empty())
            s += ", " + std::to_string(rep.notable.size()) + " notable file" +
                 (rep.notable.size() == 1 ? "" : "s");
    }
    if (passes.sbom) {
        if (!s.empty()) s += ", ";
        s += std::to_string(rep.components.size()) + " component";
        if (rep.components.size() != 1) s += "s";
    }
    if (passes.cve) {
        if (!s.empty()) s += ", ";
        s += std::to_string(rep.cves.size()) + " CVE";
        if (rep.cves.size() != 1) s += "s";
        size_t kapp = 0;
        for (const auto& k : rep.kernel_cves)
            if (k.applicable) ++kapp;
        if (!rep.kernel_cves.empty())
            s += ", " + std::to_string(kapp) + " kernel CVE" + (kapp == 1 ? "" : "s") +
                 " (of " + std::to_string(rep.kernel_cves.size()) + " in range)";
    }
    if (passes.licenses) {
        std::vector<std::string> ids;
        for (const auto& h : rep.licenses)
            if (std::find(ids.begin(), ids.end(), h.finding.type) == ids.end())
                ids.push_back(h.finding.type);
        if (!s.empty()) s += ", ";
        s += std::to_string(ids.size()) + " license";
        if (ids.size() != 1) s += "s";
    }
    if (s.empty()) s = "no findings";
    s += " across " + std::to_string(rep.file_count) + " file";
    if (rep.file_count != 1) s += "s";
    return s;
}

}  // namespace

std::string emit_report_json(const Report& rep, const Passes& passes) {
    std::string o;
    o += "{";
    bool first = true;
    kv_num(o, "schema_version", MT_SCHEMA_VERSION, first);
    kv_str(o, "root", rep.root, first);
    kv_bool(o, "is_dir", rep.is_dir, first);
    kv_num(o, "file_count", rep.file_count, first);
    kv_num(o, "bytes_scanned", rep.bytes_scanned, first);
    kv_str(o, "summary", make_summary(rep, passes), first);
    if (!rep.kernel_version.empty()) kv_str(o, "kernel_version", rep.kernel_version, first);
    if (rep.has_kconfig) kv_bool(o, "has_kconfig", true, first);

    if (passes.secrets) {
        o += ",\"secrets\":[";
        for (size_t i = 0; i < rep.secrets.size(); ++i) {
            if (i) o += ",";
            emit_hit(o, rep.secrets[i]);
        }
        o += "]";
    }
    // Notable files come from the secrets path rules and the SBOM kconfig scan.
    if (passes.secrets || passes.sbom) {
        o += ",\"notable\":[";
        for (size_t i = 0; i < rep.notable.size(); ++i) {
            if (i) o += ",";
            emit_hit(o, rep.notable[i]);
        }
        o += "]";
    }

    if (passes.sbom) {
        o += ",\"components\":[";
        for (size_t i = 0; i < rep.components.size(); ++i) {
            if (i) o += ",";
            emit_component(o, rep.components[i]);
        }
        o += "]";
    }

    if (passes.cve) {
        o += ",\"cves\":[";
        for (size_t i = 0; i < rep.cves.size(); ++i) {
            if (i) o += ",";
            emit_cve(o, rep.cves[i]);
        }
        o += "]";
        o += ",\"kernel_cves\":[";
        for (size_t i = 0; i < rep.kernel_cves.size(); ++i) {
            const auto& k = rep.kernel_cves[i];
            if (i) o += ",";
            o += "{";
            bool kf = true;
            kv_str(o, "cve", k.cve, kf);
            kv_str(o, "impact", k.impact, kf);
            kv_str(o, "state",
                   k.state == KcveState::Applicable
                       ? "applicable"
                       : (k.state == KcveState::RuledOut ? "ruled_out" : "undetermined"),
                   kf);
            kv_bool(o, "applicable", k.applicable, kf);
            kv_str(o, "reason", k.reason, kf);
            kv_str(o, "note", k.note, kf);
            kv_str(o, "source", k.source, kf);  // "curated" or "kernel.org"
            if (k.kev) kv_bool(o, "kev", true, kf);
            if (k.epss >= 0) {
                char b[16];
                std::snprintf(b, sizeof(b), "%.4f", k.epss);
                if (!kf) o += ",";
                kf = false;
                o += "\"epss\":";
                o += b;
            }
            o += "}";
        }
        o += "]";

        // Metadata that makes the curated, non-exhaustive nature of the kernel
        // scan machine-readable: an empty "kernel_cves" means "none of the curated
        // set is in range", not "this kernel has no known CVEs". LLM/tool callers
        // read this rather than inferring exhaustiveness from the array length.
        if (!rep.kernel_version.empty()) {
            // Curated (kconfig-gated) and feed (kernel.org, version-matched) are
            // counted separately; the curated summary is not diluted by the feed.
            size_t kapp = 0, kunk = 0, kruled = 0, cur = 0, feed = 0;
            for (const auto& k : rep.kernel_cves) {
                if (k.source == "kernel.org") { ++feed; continue; }
                ++cur;
                if (k.state == KcveState::Applicable) ++kapp;
                else if (k.state == KcveState::Unknown) ++kunk;
                else ++kruled;
            }
            o += ",\"kernel_cve_scan\":{";
            bool sf = true;
            kv_str(o, "method", rep.kernel_cves_full ? "curated+kernel.org" : "curated-checklist", sf);
            // The full kernel.org feed IS a complete version-matched enumeration.
            kv_bool(o, "exhaustive", rep.kernel_cves_full, sf);
            kv_num(o, "curated_total", kernel_cve_curated_total(), sf);
            kv_num(o, "curated_in_range", cur, sf);
            kv_num(o, "applicable", kapp, sf);
            kv_num(o, "undetermined", kunk, sf);
            kv_num(o, "ruled_out", kruled, sf);
            if (rep.kernel_cves_full) kv_num(o, "feed_in_range", feed, sf);
            kv_str(o, "note",
                   rep.kernel_cves_full
                       ? "curated entries are kconfig-gated; feed entries (source "
                         "\"kernel.org\") are version-matched, confirm the backport"
                       : "curated high-signal set of widely-exploited kernel bugs, not every "
                         "CVE affecting this version; run --kernel-cves-all for the full feed",
                   sf);
            o += "}";
        }

        // Structured config evidence behind the kernel-CVE gating: source, whether
        // a verbatim .config was recovered, hardening posture, and the per-option
        // On/Off/Unknown state with the evidence that decided it.
        const KernelConfigView& kcv = rep.kcv;
        std::string src = kcv.authoritative
                              ? (rep.kconfig_source.empty() ? "recovered" : rep.kconfig_source)
                              : ((kcv.kallsyms_complete || kcv.modules_seen || !kcv.enabled.empty())
                                     ? "inferred"
                                     : "none");
        o += ",\"kernel_config\":{";
        bool cf = true;
        kv_str(o, "source", src, cf);
        kv_bool(o, "recovered", !rep.kconfig_text.empty(), cf);
        if (kcv.authoritative) {
            kv_num(o, "options_enabled", static_cast<double>(kcv.enabled.size()), cf);
            // Tri-state hardening posture: enabled / disabled / not_available.
            o += ",\"hardening\":[";
            bool hf = true;
            for (const auto& it : kernel_hardening(rep.kconfig_text)) {
                const char* st = it.state == HardState::On    ? "enabled"
                                 : it.state == HardState::Off ? "disabled"
                                                              : "not_available";
                if (!hf) o += ",";
                hf = false;
                o += "{";
                bool nf = true;
                kv_str(o, "name", it.name, nf);
                kv_str(o, "state", st, nf);
                o += "}";
            }
            o += "]";
        }
        o += ",\"options\":[";
        bool first_opt = true;
        for (const auto& opt : gating_options()) {
            std::string ev;
            KcveState st = config_option_state(kcv, opt, ev);
            const char* ss = st == KcveState::Applicable ? "on"
                             : st == KcveState::RuledOut  ? "off"
                                                          : "unknown";
            if (!first_opt) o += ",";
            first_opt = false;
            o += "{";
            bool of = true;
            kv_str(o, "name", opt, of);
            kv_str(o, "state", ss, of);
            if (!ev.empty()) kv_str(o, "evidence", ev, of);
            o += "}";
        }
        o += "]}";
    }

    if (passes.licenses) {
        // Aggregate by license id: count + every distinct file path + best tier.
        // JSON is the machine view, so it always carries the complete path list
        // (the human --license-paths flag does not gate this).
        struct Agg { std::vector<std::string> paths; std::string tier; uint8_t conf = 0; };
        std::vector<std::pair<std::string, Agg>> agg;
        for (const auto& h : rep.licenses) {
            auto it = std::find_if(agg.begin(), agg.end(),
                                   [&](const auto& p) { return p.first == h.finding.type; });
            if (it == agg.end()) {
                agg.push_back({h.finding.type,
                               {{h.path}, h.finding.confidence_tier, h.finding.confidence}});
            } else {
                it->second.paths.push_back(h.path);
                if (h.finding.confidence > it->second.conf) {
                    it->second.conf = h.finding.confidence;
                    it->second.tier = h.finding.confidence_tier;
                }
            }
        }
        std::sort(agg.begin(), agg.end(), [](const auto& a, const auto& b) {
            if (a.second.paths.size() != b.second.paths.size())
                return a.second.paths.size() > b.second.paths.size();
            return a.first < b.first;
        });
        o += ",\"licenses\":[";
        for (size_t i = 0; i < agg.size(); ++i) {
            if (i) o += ",";
            o += "{";
            bool first = true;
            kv_str(o, "license", agg[i].first, first);
            kv_num(o, "count", agg[i].second.paths.size(), first);
            kv_str(o, "confidence_tier", agg[i].second.tier, first);
            o += ",\"paths\":[";
            for (size_t p = 0; p < agg[i].second.paths.size(); ++p) {
                if (p) o += ",";
                o += "\"";
                json_escape(o, agg[i].second.paths[p]);
                o += "\"";
            }
            o += "]}";
        }
        o += "]";
    }

    o += ",\"errors\":[";
    for (size_t i = 0; i < rep.errors.size(); ++i) {
        if (i) o += ",";
        o += "{\"path\":\"";
        json_escape(o, rep.errors[i].first);
        o += "\",\"reason\":\"";
        json_escape(o, rep.errors[i].second);
        o += "\"}";
    }
    o += "]";

    o += "}";
    return o;
}

}  // namespace ft
