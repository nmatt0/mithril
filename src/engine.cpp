#include "engine.hpp"

#include <algorithm>

#include "validators.hpp"

namespace ft {

// ---- M1 glob matching -----------------------------------------------------
// '*' matches within a path segment (not '/'); '**' matches across segments;
// '?' matches a single non-'/' char. Anchored at both ends. Recursion depth is
// bounded by the (short) pattern, so this is safe on adversarial paths.
static bool gm(const char* p, const char* s) {
    while (*p) {
        if (*p == '*') {
            if (p[1] == '*') {
                while (*p == '*') ++p;   // collapse
                if (*p == '/') ++p;      // "**/x" also matches "x" at root
                if (!*p) return true;    // trailing ** matches the rest
                for (;; ++s) {
                    if (gm(p, s)) return true;
                    if (!*s) return false;
                }
            } else {
                ++p;
                for (;;) {
                    if (gm(p, s)) return true;
                    if (!*s || *s == '/') return false;
                    ++s;
                }
            }
        } else if (*p == '?') {
            if (!*s || *s == '/') return false;
            ++p;
            ++s;
        } else {
            if (*s != *p) return false;
            ++p;
            ++s;
        }
    }
    return !*s;
}

bool glob_match(const std::string& glob, const std::string& path) {
    return gm(glob.c_str(), path.c_str());
}

// ---- M2 scanning mechanics ------------------------------------------------
namespace {

// Cheap "text-ish?" gate: text/config and base64 are mostly printable;
// compressed/encrypted data is not. Sample the head of the block.
bool block_textish(std::span<const uint8_t> d) {
    size_t take = std::min<size_t>(d.size(), 512);
    if (take == 0) return false;
    size_t printable = 0, zeros = 0;
    for (size_t i = 0; i < take; ++i) {
        uint8_t c = d[i];
        if (c == 9 || c == 10 || c == 13 || (c >= 0x20 && c < 0x7F)) ++printable;
        else if (c == 0) ++zeros;
    }
    return (printable * 100 >= take * 60) ||
           (printable * 100 >= take * 25 && zeros * 100 >= take * 25);
}

}  // namespace

Engine::Engine(std::vector<ContentRule> content, std::vector<PathRule> paths)
    : content_(std::move(content)), paths_(std::move(paths)) {
    for (uint32_t ri = 0; ri < content_.size(); ++ri) {
        for (const auto& kw : content_[ri].anchors) {
            std::vector<uint8_t> bytes(kw.begin(), kw.end());
            ac_.add(bytes, static_cast<uint32_t>(id_to_rule_.size()));
            id_to_rule_.push_back(ri);
        }
    }
    ac_.build();
}

void Engine::run_rules(const Reader& r, const char* enc, size_t region_off, size_t region_len,
                       size_t raw_base, std::vector<Finding>& out) const {
    ac_.find(r.data(), 0, [&](size_t off, uint32_t id) -> bool {
        const ContentRule& rule = content_[id_to_rule_[id]];
        auto mm = rule.matcher(r, off);
        if (!mm) return true;
        std::string tok = token_str(r, off, mm->len);
        if (is_false_positive(tok)) return true;
        if (rule.min_entropy > 0.0 && token_entropy(tok) < rule.min_entropy) return true;

        Finding f;
        f.offset = enc ? region_off : raw_base + off;
        f.size = enc ? region_len : mm->len;
        f.type = rule.type;
        f.category = rule.category;
        f.label = mm->label.empty() ? redact(tok) : mm->label;

        std::string enc_note = enc ? std::string(" [") + enc + "-encoded]" : "";
        if (!mm->description.empty())
            f.description = mm->description + enc_note;
        else if (!rule.description.empty())
            f.description = rule.description + enc_note;
        else
            f.description = "Candidate " + rule.type + enc_note;

        std::string ev = mm->evidence.empty() ? "offline pattern match" : mm->evidence;
        if (enc) ev += std::string(" (") + enc + ")";
        f.set_confidence(static_cast<Confidence>(mm->confidence), ev);
        out.push_back(std::move(f));
        return true;
    });
}

std::vector<Finding> Engine::scan_content(const Reader& r) const {
    std::vector<Finding> out;
    const std::span<const uint8_t> data = r.data();
    const size_t n = data.size();

    constexpr size_t BLOCK = 4096;
    for (size_t seg = 0; seg < n;) {
        if (!block_textish(data.subspan(seg, std::min(BLOCK, n - seg)))) {
            seg += BLOCK;
            continue;
        }
        size_t end = seg;
        while (end < n && block_textish(data.subspan(end, std::min(BLOCK, n - end))))
            end += std::min(BLOCK, n - end);
        const size_t base = seg;
        const size_t len = end - seg;
        std::span<const uint8_t> sub = data.subspan(base, len);
        Reader sr(sub);

        // 1. raw
        run_rules(sr, nullptr, 0, 0, base, out);

        // 2. base64 decode-then-scan
        for (size_t i = 0; i < len;) {
            if (!is_b64_char(sub[i])) { ++i; continue; }
            size_t j = i;
            while (j < len && is_b64_char(sub[j])) ++j;
            size_t runlen = j - i;
            if (runlen >= 24) {
                auto dec = base64_decode(sub.subspan(i, runlen));
                if (dec.size() >= 8) {
                    Reader dr(std::span<const uint8_t>(dec.data(), dec.size()));
                    run_rules(dr, "base64", base + i, runlen, 0, out);
                }
            }
            i = j;
        }

        // 3. utf16le collapse-then-scan
        for (size_t i = 0; i + 1 < len;) {
            if (sub[i] >= 0x20 && sub[i] < 0x7F && sub[i + 1] == 0) {
                size_t start = i;
                std::vector<uint8_t> buf;
                while (i + 1 < len && sub[i] >= 0x20 && sub[i] < 0x7F && sub[i + 1] == 0) {
                    buf.push_back(sub[i]);
                    i += 2;
                }
                if (buf.size() >= 16) {
                    Reader dr(std::span<const uint8_t>(buf.data(), buf.size()));
                    run_rules(dr, "utf16le", base + start, i - start, 0, out);
                }
            } else {
                ++i;
            }
        }
        seg = end + BLOCK;
    }

    // Dedup identical (offset,type) hits.
    std::sort(out.begin(), out.end(), [](const Finding& a, const Finding& b) {
        if (a.offset != b.offset) return a.offset < b.offset;
        return a.type < b.type;
    });
    out.erase(std::unique(out.begin(), out.end(),
                          [](const Finding& a, const Finding& b) {
                              return a.offset == b.offset && a.type == b.type;
                          }),
              out.end());
    return out;
}

std::vector<Finding> Engine::scan_paths(const std::string& relpath, size_t filesize) const {
    std::vector<Finding> out;
    for (const auto& pr : paths_) {
        if (!glob_match(pr.glob, relpath)) continue;
        Finding f;
        f.offset = 0;
        f.size = filesize;
        f.type = pr.type;
        f.category = pr.category;
        f.label = relpath;
        f.description = pr.description;
        f.set_confidence(Confidence::Structural, "matched path rule: " + pr.glob);
        out.push_back(std::move(f));
    }
    return out;
}

}  // namespace ft
