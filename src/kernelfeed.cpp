#include "kernelfeed.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>

#include "io_util.hpp"
#include "jsonparse.hpp"
#include "strutil.hpp"
#include "version.hpp"

namespace ft {

namespace {

// A dotted numeric version like "6.6" or "5.10.220" (digits and dots only).
bool is_verish(const std::string& s) {
    if (s.empty() || !std::isdigit(static_cast<unsigned char>(s[0]))) return false;
    for (char c : s)
        if (c != '.' && !std::isdigit(static_cast<unsigned char>(c))) return false;
    return true;
}

// "X.Y" from "X.Y.Z" (the stable-branch key); the input if it has < 2 components.
std::string series(const std::string& v) {
    size_t d1 = v.find('.');
    if (d1 == std::string::npos) return v;
    size_t d2 = v.find('.', d1 + 1);
    return d2 == std::string::npos ? v : v.substr(0, d2);
}

// A mainline release (no stable-branch patch level): "X.Y" or "X.Y.0". Firmware
// kernels are almost always stable (X.Y.Z, Z>0); this gates the coarse mainline
// interval so it never false-matches a stable release in a different branch.
bool is_mainline(const std::string& v) {
    size_t d1 = v.find('.');
    if (d1 == std::string::npos) return true;  // "6" — degenerate, treat as mainline
    size_t d2 = v.find('.', d1 + 1);
    if (d2 == std::string::npos) return true;  // "X.Y"
    return v.substr(d2 + 1) == "0";            // "X.Y.0"
}

// V in [lo, hi): lo inclusive, hi exclusive (hi empty == open end).
bool in_range(const std::string& v, const KfRange& r) {
    if (!r.introduced.empty() && deb_vercmp(v, r.introduced) < 0) return false;
    if (!r.fixed.empty() && deb_vercmp(v, r.fixed) >= 0) return false;
    return true;
}

}  // namespace

// --- reconstruction from a raw kernel.org CVE-5.0 record --------------------
// kernel.org records carry two `affected` blocks. The defaultStatus=unaffected
// block lists explicit `status:affected` [version,lessThan) intervals, each
// self-contained within one stable branch (safe to match by raw compare). The
// defaultStatus=affected block lists the fix points as `status:unaffected`
// entries: `version:"0" lessThan:M` (mainline introduced at M),
// `version:X lessThanOrEqual:"*"` (mainline fixed at X), and
// `version:F lessThanOrEqual:"S.*"` (stable branch S fixed at F). From a branch
// fix we reconstruct [S, F) for branches the first block did not already cover
// (there the bug predates the branch, so the whole branch up to the fix is
// affected). Semver `affected` intervals are precise; a non-semver `custom`
// affected range is coarse -> `broad`.
bool kernel_feed_entry_from_cna(const JsonValue& cna, const std::string& cve_id,
                                KernelFeedEntry& out) {
    out = KernelFeedEntry{};
    out.cve = cve_id;

    std::vector<std::string> block0_series;  // series with an explicit affected interval
    std::vector<std::pair<std::string, std::string>> branch_fix;  // series -> fixed
    std::string m_intro, m_fix;

    const JsonValue* affected = cna.find("affected");
    if (!affected || !affected->is_array()) return false;
    for (const JsonValue& a : affected->arr) {
        const JsonValue* versions = a.find("versions");
        if (!versions || !versions->is_array()) continue;
        for (const JsonValue& v : versions->arr) {
            const std::string ver = v.get_str("version");
            const std::string lt = v.get_str("lessThan");
            const std::string lte = v.get_str("lessThanOrEqual");
            const std::string st = v.get_str("status");
            const std::string vt = v.get_str("versionType");
            if (st == "affected" && !lt.empty() && is_verish(ver) && is_verish(lt)) {
                if (vt == "semver") {
                    out.ranges.push_back({ver, lt});
                    std::string s = series(ver);
                    if (std::find(block0_series.begin(), block0_series.end(), s) ==
                        block0_series.end())
                        block0_series.push_back(s);
                } else {
                    out.broad.push_back({ver, lt});  // "custom" wide range
                }
            } else if (st == "unaffected") {
                if (ver == "0" && !lt.empty() && is_verish(lt)) {
                    m_intro = lt;  // unaffected below lt -> introduced at lt (mainline)
                } else if (lte == "*" && is_verish(ver)) {
                    m_fix = ver;   // original_commit_for_fix -> mainline fixed at ver
                } else if (lte.size() > 2 && lte.substr(lte.size() - 2) == ".*" &&
                           is_verish(ver)) {
                    branch_fix.emplace_back(series(ver), ver);  // branch S fixed at ver
                }
            }
        }
    }

    // Branch fixes for branches the explicit intervals did not cover: the bug
    // predates the branch fork, so the branch is affected from its base up to F.
    for (const auto& [s, f] : branch_fix)
        if (std::find(block0_series.begin(), block0_series.end(), s) == block0_series.end())
            out.ranges.push_back({s, f});

    if (is_verish(m_intro) && is_verish(m_fix)) out.mainline = {m_intro, m_fix};

    // CVSS (only ~37% of records carry one) and a short title.
    if (const JsonValue* metrics = cna.find("metrics"); metrics && metrics->is_array())
        for (const JsonValue& m : metrics->arr) {
            const JsonValue* c = m.find("cvssV3_1");
            if (!c) c = m.find("cvssV3_0");
            if (!c) c = m.find("cvssV4_0");
            if (c && c->is_object()) {
                out.score = c->get_num("baseScore", -1.0);
                out.severity = c->get_str("baseSeverity");
                if (out.score >= 0 || !out.severity.empty()) break;
            }
        }
    out.summary = cna.get_str("title");

    return !out.ranges.empty() || !out.broad.empty() ||
           (!out.mainline.introduced.empty() && !out.mainline.fixed.empty());
}

// --- on-disk index format ---------------------------------------------------
std::string write_kernel_feed_index(const std::vector<KernelFeedEntry>& entries,
                                    unsigned long long generated) {
    auto rng = [](std::string& o, const std::vector<KfRange>& rs) {
        o += "[";
        for (size_t i = 0; i < rs.size(); ++i) {
            if (i) o += ",";
            o += "[\"";
            json_escape(o, rs[i].introduced);
            o += "\",\"";
            json_escape(o, rs[i].fixed);
            o += "\"]";
        }
        o += "]";
    };
    std::string o = "{\"schema\":\"mithril-kernel-cve-1\",\"source\":\"kernel.org Linux CNA\","
                    "\"generated\":";
    o += std::to_string(generated);
    o += ",\"cves\":[";
    for (size_t i = 0; i < entries.size(); ++i) {
        const KernelFeedEntry& e = entries[i];
        if (i) o += ",";
        o += "{\"id\":\"";
        json_escape(o, e.cve);
        o += "\",\"ranges\":";
        rng(o, e.ranges);
        if (!e.broad.empty()) {
            o += ",\"broad\":";
            rng(o, e.broad);
        }
        if (!e.mainline.introduced.empty() && !e.mainline.fixed.empty()) {
            o += ",\"mainline\":[\"";
            json_escape(o, e.mainline.introduced);
            o += "\",\"";
            json_escape(o, e.mainline.fixed);
            o += "\"]";
        }
        if (e.score >= 0) {
            char b[16];
            std::snprintf(b, sizeof(b), "%.1f", e.score);
            o += ",\"score\":";
            o += b;
        }
        if (!e.severity.empty()) {
            o += ",\"sev\":\"";
            json_escape(o, e.severity);
            o += "\"";
        }
        if (!e.summary.empty()) {
            o += ",\"sum\":\"";
            json_escape(o, e.summary);
            o += "\"";
        }
        o += "}";
    }
    o += "]}";
    return o;
}

std::optional<std::vector<KernelFeedEntry>> load_kernel_feed(const std::string& path) {
    auto body = read_file(path);
    if (!body) return std::nullopt;
    auto doc = json_parse(*body);
    if (!doc || !doc->is_object()) return std::nullopt;
    const JsonValue* cves = doc->find("cves");
    if (!cves || !cves->is_array()) return std::nullopt;

    auto parse_ranges = [](const JsonValue* arr, std::vector<KfRange>& out) {
        if (!arr || !arr->is_array()) return;
        for (const JsonValue& r : arr->arr) {
            if (!r.is_array() || r.arr.size() < 2) continue;
            if (r.arr[0].type != JsonValue::Type::String) continue;
            out.push_back({r.arr[0].str, r.arr[1].str});
        }
    };

    std::vector<KernelFeedEntry> feed;
    feed.reserve(cves->arr.size());
    for (const JsonValue& c : cves->arr) {
        if (!c.is_object()) continue;
        KernelFeedEntry e;
        e.cve = c.get_str("id");
        if (e.cve.empty()) continue;
        parse_ranges(c.find("ranges"), e.ranges);
        parse_ranges(c.find("broad"), e.broad);
        if (const JsonValue* ml = c.find("mainline"); ml && ml->is_array() && ml->arr.size() >= 2 &&
                                                      ml->arr[0].type == JsonValue::Type::String)
            e.mainline = {ml->arr[0].str, ml->arr[1].str};
        e.score = c.get_num("score", -1.0);
        e.severity = c.get_str("sev");
        e.summary = c.get_str("sum");
        feed.push_back(std::move(e));
    }
    return feed;
}

// --- matcher ----------------------------------------------------------------
std::string kernel_feed_basis(const std::string& version, const KernelFeedEntry& e) {
    if (version.empty()) return "";
    for (const KfRange& r : e.ranges)
        if (in_range(version, r)) return "branch-exact";
    for (const KfRange& r : e.broad)
        if (in_range(version, r)) return "broad-range";
    if (is_mainline(version) && !e.mainline.introduced.empty() && !e.mainline.fixed.empty() &&
        in_range(version, e.mainline))
        return "broad-range";
    return "";
}

std::vector<KernelCveResult> kernel_feed_scan(const std::string& version,
                                              const std::vector<KernelFeedEntry>& feed) {
    std::vector<KernelCveResult> out;
    if (version.empty()) return out;
    for (const KernelFeedEntry& e : feed) {
        std::string basis = kernel_feed_basis(version, e);
        if (basis.empty()) continue;
        KernelCveResult r;
        r.cve = e.cve;
        r.impact = e.severity;  // "HIGH"/"MEDIUM"/... from CVSS, or "" if none
        r.note = e.summary;
        r.state = KcveState::Applicable;  // the feed carries no CONFIG data to gate on
        r.applicable = true;
        r.reason = (basis == "branch-exact") ? "in range for this branch (kernel.org)"
                                             : "in range, verify backport (kernel.org)";
        r.source = "kernel.org";
        out.push_back(std::move(r));
    }
    std::sort(out.begin(), out.end(),
              [](const KernelCveResult& a, const KernelCveResult& b) { return a.cve < b.cve; });
    return out;
}

}  // namespace ft
