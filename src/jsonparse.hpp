// jsonparse.hpp — a minimal, dependency-free JSON *reader* (header-only).
//
// mithril hand-emits its own JSON (json.cpp) but needs to *read* JSON from
// external sources — a moria `-j` tree, language manifests, and the offline
// OSV/NVD vuln mirror later. This is a small recursive-descent parser returning a
// JsonValue DOM. Not a performance or spec-completeness showcase — it accepts
// standard JSON (objects, arrays, strings with escapes incl. \uXXXX + surrogate
// pairs, numbers, true/false/null) and returns std::nullopt on malformed input.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ft {

struct JsonMember;  // forward: an object's key/value pair (defined after JsonValue)

struct JsonValue {
    enum class Type { Null, Bool, Number, String, Array, Object };
    Type type = Type::Null;

    bool b = false;
    double num = 0.0;
    std::string str;
    // std::vector supports an incomplete element type (unlike std::pair, which
    // is why obj uses a named member struct rather than pair<string, JsonValue>).
    std::vector<JsonValue> arr;
    std::vector<JsonMember> obj;

    bool is_object() const { return type == Type::Object; }
    bool is_array() const { return type == Type::Array; }
    bool is_string() const { return type == Type::String; }

    // Object member lookup by key (linear; objects here are small). nullptr if
    // this is not an object or the key is absent. Defined out of line below,
    // once JsonMember is complete.
    const JsonValue* find(std::string_view key) const;

    // Convenience typed getters with defaults (never throw).
    std::string get_str(std::string_view key, std::string def = "") const {
        const JsonValue* v = find(key);
        return (v && v->type == Type::String) ? v->str : def;
    }
    bool get_bool(std::string_view key, bool def = false) const {
        const JsonValue* v = find(key);
        return (v && v->type == Type::Bool) ? v->b : def;
    }
    double get_num(std::string_view key, double def = 0.0) const {
        const JsonValue* v = find(key);
        return (v && v->type == Type::Number) ? v->num : def;
    }
};

struct JsonMember {
    std::string key;
    JsonValue value;
};

inline const JsonValue* JsonValue::find(std::string_view key) const {
    if (type != Type::Object) return nullptr;
    for (const auto& m : obj)
        if (m.key == key) return &m.value;
    return nullptr;
}

namespace jsondetail {

struct Parser {
    std::string_view s;
    size_t i = 0;
    int depth = 0;  // current object/array nesting, bounded by kMaxDepth

    // Cap on nesting depth. Recursive descent uses one native stack frame per
    // level, so unbounded nesting from untrusted input (a crafted package-lock
    // .json / composer.lock in a scanned image, a JWT payload, an OSV/NVD feed,
    // or a --rules file) would overflow the stack and crash. Real JSON here is
    // shallow (OSV/NVD records, lockfiles); 256 is generous headroom while still
    // failing a stack-smashing input as ordinary malformed JSON (nullopt).
    static constexpr int kMaxDepth = 256;

    void ws() {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) ++i;
    }

    bool parse_value(JsonValue& out) {
        ws();
        if (i >= s.size()) return false;
        switch (s[i]) {
            case '{':
            case '[': {
                if (depth >= kMaxDepth) return false;  // too deep -> malformed
                ++depth;
                bool ok = (s[i] == '{') ? parse_object(out) : parse_array(out);
                --depth;
                return ok;
            }
            case '"': {
                out.type = JsonValue::Type::String;
                return parse_string(out.str);
            }
            case 't': case 'f': return parse_bool(out);
            case 'n': return parse_null(out);
            default: return parse_number(out);
        }
    }

    static void encode_utf8(uint32_t cp, std::string& o) {
        if (cp <= 0x7F) {
            o += static_cast<char>(cp);
        } else if (cp <= 0x7FF) {
            o += static_cast<char>(0xC0 | (cp >> 6));
            o += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp <= 0xFFFF) {
            o += static_cast<char>(0xE0 | (cp >> 12));
            o += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            o += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            o += static_cast<char>(0xF0 | (cp >> 18));
            o += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            o += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            o += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    bool hex4(uint32_t& out) {
        if (i + 4 > s.size()) return false;
        out = 0;
        for (int k = 0; k < 4; ++k) {
            char c = s[i++];
            out <<= 4;
            if (c >= '0' && c <= '9') out |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') out |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') out |= static_cast<uint32_t>(c - 'A' + 10);
            else return false;
        }
        return true;
    }

    bool parse_string(std::string& out) {
        if (s[i] != '"') return false;
        ++i;  // opening quote
        while (i < s.size()) {
            char c = s[i++];
            if (c == '"') return true;
            if (c == '\\') {
                if (i >= s.size()) return false;
                char e = s[i++];
                switch (e) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'b': out += '\b'; break;
                    case 'f': out += '\f'; break;
                    case 'n': out += '\n'; break;
                    case 'r': out += '\r'; break;
                    case 't': out += '\t'; break;
                    case 'u': {
                        uint32_t cp = 0;
                        if (!hex4(cp)) return false;
                        if (cp >= 0xD800 && cp <= 0xDBFF) {  // high surrogate
                            if (i + 2 <= s.size() && s[i] == '\\' && s[i + 1] == 'u') {
                                i += 2;
                                uint32_t lo = 0;
                                if (!hex4(lo)) return false;
                                if (lo >= 0xDC00 && lo <= 0xDFFF)
                                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                else
                                    cp = 0xFFFD;  // unpaired
                            } else {
                                cp = 0xFFFD;
                            }
                        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                            cp = 0xFFFD;  // lone low surrogate
                        }
                        encode_utf8(cp, out);
                        break;
                    }
                    default: return false;
                }
            } else {
                out += c;
            }
        }
        return false;  // unterminated
    }

    bool parse_number(JsonValue& out) {
        size_t start = i;
        if (i < s.size() && (s[i] == '-' || s[i] == '+')) ++i;
        bool any = false;
        while (i < s.size() && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.' || s[i] == 'e' ||
                                s[i] == 'E' || s[i] == '+' || s[i] == '-')) {
            ++i;
            any = true;
        }
        if (!any) return false;
        std::string tok(s.substr(start, i - start));
        try {
            out.num = std::stod(tok);
        } catch (...) {
            return false;
        }
        out.type = JsonValue::Type::Number;
        return true;
    }

    bool lit(std::string_view word) {
        if (s.substr(i, word.size()) != word) return false;
        i += word.size();
        return true;
    }
    bool parse_bool(JsonValue& out) {
        if (lit("true")) { out.type = JsonValue::Type::Bool; out.b = true; return true; }
        if (lit("false")) { out.type = JsonValue::Type::Bool; out.b = false; return true; }
        return false;
    }
    bool parse_null(JsonValue& out) {
        if (lit("null")) { out.type = JsonValue::Type::Null; return true; }
        return false;
    }

    bool parse_array(JsonValue& out) {
        out.type = JsonValue::Type::Array;
        ++i;  // [
        ws();
        if (i < s.size() && s[i] == ']') { ++i; return true; }
        while (true) {
            JsonValue v;
            if (!parse_value(v)) return false;
            out.arr.push_back(std::move(v));
            ws();
            if (i >= s.size()) return false;
            if (s[i] == ',') { ++i; continue; }
            if (s[i] == ']') { ++i; return true; }
            return false;
        }
    }

    bool parse_object(JsonValue& out) {
        out.type = JsonValue::Type::Object;
        ++i;  // {
        ws();
        if (i < s.size() && s[i] == '}') { ++i; return true; }
        while (true) {
            ws();
            if (i >= s.size() || s[i] != '"') return false;
            std::string key;
            if (!parse_string(key)) return false;
            ws();
            if (i >= s.size() || s[i] != ':') return false;
            ++i;
            JsonValue v;
            if (!parse_value(v)) return false;
            out.obj.push_back(JsonMember{std::move(key), std::move(v)});
            ws();
            if (i >= s.size()) return false;
            if (s[i] == ',') { ++i; continue; }
            if (s[i] == '}') { ++i; return true; }
            return false;
        }
    }
};

}  // namespace jsondetail

// Parse one complete JSON document. Returns nullopt on malformed input or if
// trailing non-whitespace remains.
inline std::optional<JsonValue> json_parse(std::string_view s) {
    jsondetail::Parser p{s, 0};
    JsonValue v;
    if (!p.parse_value(v)) return std::nullopt;
    p.ws();
    if (p.i != s.size()) return std::nullopt;
    return v;
}

}  // namespace ft
