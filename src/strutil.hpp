// strutil.hpp — small shared string helpers (header-only).
//
// Consolidates helpers that were copy-pasted across the parsers and emitters:
//   basename_of  — the last path component (6 identical copies in the SBOM/
//                  license/credstore parsers)
//   json_escape  — JSON string-body escaping (3 identical copies in json.cpp,
//                  sbom_emit.cpp, cveupdate.cpp)
#pragma once

#include <cstdio>
#include <string>
#include <string_view>

namespace ft {

// The last '/'-separated component of a path ("a/b/c.so" -> "c.so"); the whole
// string if there is no '/'. Used to dispatch parsers by filename.
inline std::string_view basename_of(std::string_view p) {
    size_t slash = p.find_last_of('/');
    return slash == std::string_view::npos ? p : p.substr(slash + 1);
}

// Append `s` to `out` escaped as a JSON string body (no surrounding quotes).
// Escapes ", \\, and the C0 control set; emits any control or non-ASCII byte as
// \u00XX so the result is always valid JSON/UTF-8 even for a redacted token that
// carries a raw binary byte.
inline void json_escape(std::string& out, const std::string& s) {
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: {
                unsigned char uc = static_cast<unsigned char>(c);
                if (uc < 0x20 || uc >= 0x80) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", uc);
                    out += buf;
                } else {
                    out += c;
                }
            }
        }
    }
}

}  // namespace ft
