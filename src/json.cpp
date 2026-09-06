#include "json.hpp"

#include <algorithm>
#include <cstdio>

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
            kv_bool(o, "applicable", k.applicable, kf);
            kv_str(o, "reason", k.reason, kf);
            kv_str(o, "note", k.note, kf);
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
    }

    if (passes.licenses) {
        // Aggregate by license id: count + an example path + best tier.
        struct Agg { size_t count = 0; std::string example, tier; uint8_t conf = 0; };
        std::vector<std::pair<std::string, Agg>> agg;
        for (const auto& h : rep.licenses) {
            auto it = std::find_if(agg.begin(), agg.end(),
                                   [&](const auto& p) { return p.first == h.finding.type; });
            if (it == agg.end()) {
                agg.push_back({h.finding.type, {1, h.path, h.finding.confidence_tier,
                                                h.finding.confidence}});
            } else {
                it->second.count++;
                if (h.finding.confidence > it->second.conf) {
                    it->second.conf = h.finding.confidence;
                    it->second.tier = h.finding.confidence_tier;
                    it->second.example = h.path;
                }
            }
        }
        std::sort(agg.begin(), agg.end(), [](const auto& a, const auto& b) {
            if (a.second.count != b.second.count) return a.second.count > b.second.count;
            return a.first < b.first;
        });
        o += ",\"licenses\":[";
        for (size_t i = 0; i < agg.size(); ++i) {
            if (i) o += ",";
            o += "{";
            bool first = true;
            kv_str(o, "license", agg[i].first, first);
            kv_num(o, "count", agg[i].second.count, first);
            kv_str(o, "confidence_tier", agg[i].second.tier, first);
            kv_str(o, "example_path", agg[i].second.example, first);
            o += "}";
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
