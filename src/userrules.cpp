#include "userrules.hpp"

#include <cstdio>
#include <memory>
#include <optional>
#include <regex>
#include <string>

#include "io_util.hpp"
#include "jsonparse.hpp"
#include "validators.hpp"

namespace ft {

namespace {

// Build a matcher for a content rule that has a regex: run it on a bounded
// window, anchored at the anchor offset (match_continuous). Capture group 1, if
// present, becomes the label.
std::function<std::optional<Match>(const Reader&, size_t)> regex_matcher(const std::string& pattern) {
    auto re = std::make_shared<std::regex>(pattern, std::regex::ECMAScript | std::regex::optimize);
    return [re](const Reader& r, size_t off) -> std::optional<Match> {
        constexpr size_t WINDOW = 256;  // bounded window keeps the regex ReDoS-safe
        std::string w = token_str(r, off, std::min<size_t>(WINDOW, r.size() - off));
        std::smatch m;
        if (!std::regex_search(w, m, *re, std::regex_constants::match_continuous)) return std::nullopt;
        Match mm;
        mm.len = static_cast<size_t>(m.length(0));
        mm.confidence = Confidence::Pattern;
        if (m.size() > 1 && m[1].matched) mm.label = m[1].str();
        return mm;
    };
}

}  // namespace

UserRules load_user_rules(const std::string& path) {
    auto text = read_file(path);
    if (!text) {
        UserRules ur;
        ur.error = "cannot read rule file: " + path;
        return ur;
    }
    return parse_user_rules(*text);
}

UserRules parse_user_rules(const std::string& text) {
    UserRules ur;
    auto doc = json_parse(text);
    if (!doc || !doc->is_object()) {
        ur.error = "rule file is not a JSON object";
        return ur;
    }

    // --- path_rules ---
    if (const JsonValue* pr = doc->find("path_rules")) {
        if (!pr->is_array()) {
            ur.error = "path_rules must be an array";
            return ur;
        }
        for (const JsonValue& e : pr->arr) {
            std::string glob = e.get_str("glob");
            if (glob.empty()) {
                ur.error = "a path_rule is missing \"glob\"";
                return ur;
            }
            PathRule p;
            p.glob = glob;
            p.action = PathAction::FlagNotable;
            p.category = e.get_str("category", "config");
            p.type = e.get_str("type", "user-notable");
            p.description = e.get_str("description");
            ur.paths.push_back(std::move(p));
        }
    }

    // --- content_rules ---
    if (const JsonValue* cr = doc->find("content_rules")) {
        if (!cr->is_array()) {
            ur.error = "content_rules must be an array";
            return ur;
        }
        for (const JsonValue& e : cr->arr) {
            const JsonValue* anchors = e.find("anchors");
            if (!anchors || !anchors->is_array() || anchors->arr.empty()) {
                ur.error = "a content_rule is missing a non-empty \"anchors\" array";
                return ur;
            }
            ContentRule c;
            c.type = e.get_str("type", "user-content");
            c.category = e.get_str("category", "config");
            c.description = e.get_str("description");
            c.min_entropy = e.get_num("min_entropy", 0.0);
            for (const JsonValue& a : anchors->arr)
                if (a.is_string()) c.anchors.push_back(a.str);
            if (c.anchors.empty()) {
                ur.error = "a content_rule has no string anchors";
                return ur;
            }

            std::string rx = e.get_str("regex");
            if (!rx.empty()) {
                try {
                    c.matcher = regex_matcher(rx);
                } catch (const std::regex_error& ex) {
                    ur.error = "invalid regex in content_rule \"" + c.type + "\": " + ex.what();
                    return ur;
                }
            } else {
                // Keyword presence: all anchors share one length-agnostic matcher.
                // Each anchor may differ in length, so bind per-anchor below.
                // Simplest correct approach: the matcher recovers the anchor length
                // from the shortest anchor is wrong; instead match the exact anchor
                // at the offset. We store the anchors and match the longest that fits.
                std::vector<std::string> keys = c.anchors;
                c.matcher = [keys](const Reader& r, size_t off) -> std::optional<Match> {
                    for (const auto& k : keys) {
                        if (r.matches_at(off, std::span<const uint8_t>(
                                                  reinterpret_cast<const uint8_t*>(k.data()),
                                                  k.size())))
                            return Match{k.size(), Confidence::Pattern, "", k, "", ""};
                    }
                    return std::nullopt;
                };
            }
            ur.content.push_back(std::move(c));
        }
    }

    return ur;
}

}  // namespace ft
