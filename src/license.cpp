#include "license.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>
#include <unordered_set>

namespace ft {

namespace {

std::string_view as_sv(std::span<const uint8_t> d) {
    return std::string_view(reinterpret_cast<const char*>(d.data()), d.size());
}

std::string lower(std::string_view s) {
    std::string o(s);
    for (char& c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return o;
}

// Is this file (by basename) a license file worth text-matching?
bool is_license_filename(std::string_view base) {
    std::string b = lower(base);
    static const char* names[] = {"license", "licence", "copying", "notice", "copyright",
                                  "unlicense", "eula"};
    for (const char* n : names)
        if (b == n || b.rfind(std::string(n) + ".", 0) == 0 ||  // license.txt / copying.lib
            (b.size() > std::string(n).size() && b.rfind(std::string(n)) != std::string::npos &&
             b.rfind(".license") != std::string::npos))
            return true;
    // *.license
    if (b.size() >= 8 && b.rfind(".license") == b.size() - 8) return true;
    return false;
}

// Should this path be text-matched for a license? True if the basename OR any
// ancestor directory component looks like a license file. The ancestor case
// catches a decompressed license blob: moria expands "NOTICE.xml.gz" to
// ".../NOTICE.xml.gz.extracted/0x0-gzip/decompressed", so the license *text*
// lives in a file named "decompressed" under a license-named ancestor. Matching
// any component recovers it (and handles LICENSES/ or common-licenses/ trees).
bool is_license_path(std::string_view relpath) {
    size_t start = 0;
    while (start <= relpath.size()) {
        size_t slash = relpath.find('/', start);
        std::string_view comp =
            relpath.substr(start, slash == std::string_view::npos ? std::string_view::npos
                                                                   : slash - start);
        if (!comp.empty() && is_license_filename(comp)) return true;
        if (slash == std::string_view::npos) break;
        start = slash + 1;
    }
    return false;
}

}  // namespace

std::vector<std::string> identify_license_text(std::span<const uint8_t> data) {
    // Match on a bounded prefix. Aggregated Android NOTICE files bundle dozens of
    // licenses and run to a few MB, so the cap is generous (16 MiB); a per-license
    // marker is a single substring scan, and license-named files are rare, so the
    // cost is negligible. The cap only guards against a pathological huge input.
    std::string_view full = as_sv(data);
    std::string_view text = full.substr(0, std::min<size_t>(full.size(), 16u << 20));
    auto has = [&](std::string_view needle) { return text.find(needle) != std::string_view::npos; };

    std::vector<std::string> out;
    auto add = [&](const char* id) {
        if (std::find(out.begin(), out.end(), id) == out.end()) out.emplace_back(id);
    };

    // GNU family — disambiguate Affero/Lesser/Library and version by the dated
    // title line. LGPL 2.0 (1991) is titled "Library General Public License";
    // the 2.1 (1999) rename to "Lesser" is why v2 needs its own marker (without
    // it an LGPL-2.0 COPYING is mis-identified as GPL-2.0).
    bool affero = has("GNU AFFERO GENERAL PUBLIC LICENSE") || has("GNU Affero");
    bool lesser = has("GNU LESSER GENERAL PUBLIC LICENSE") || has("Lesser General Public");
    bool library = has("GNU LIBRARY GENERAL PUBLIC LICENSE") || has("Library General Public License");
    if (has("Version 3, 29 June 2007")) {
        if (affero) add("AGPL-3.0");
        else if (lesser) add("LGPL-3.0");
        else add("GPL-3.0");
    }
    if (has("Version 2.1, February 1999")) add("LGPL-2.1");
    if (has("Version 2, June 1991")) {
        if (library) add("LGPL-2.0");
        else if (!lesser) add("GPL-2.0");
    }
    if (has("Version 1, February 1989")) add("GPL-1.0");

    if (has("Apache License") && has("Version 2.0")) add("Apache-2.0");
    if (has("Mozilla Public License Version 2.0")) add("MPL-2.0");
    if (has("Mozilla Public License Version 1.1") || has("Mozilla Public License, version 1.1"))
        add("MPL-1.1");
    if (has("Eclipse Public License"))
        add(has("v 2.0") || has("v. 2.0") || has("Version 2.0") ? "EPL-2.0" : "EPL-1.0");
    if (has("COMMON DEVELOPMENT AND DISTRIBUTION LICENSE")) add("CDDL-1.0");
    if (has("Artistic License")) add(has("Version 2") ? "Artistic-2.0" : "Artistic-1.0");
    if (has("PYTHON SOFTWARE FOUNDATION LICENSE")) add("Python-2.0");
    if (has("OpenSSL License") || has("Original SSLeay License")) add("OpenSSL");
    // Boost / fonts / codecs / X11 / BerkeleyDB / curl / NCSA / Creative Commons.
    if (has("Boost Software License")) add("BSL-1.0");
    if (has("SIL Open Font License") || has("SIL OPEN FONT LICENSE")) add("OFL-1.1");
    if (has("PNG Reference Library") || has("libpng license") ||
        has("This code is released under the libpng"))
        add("Libpng");
    if (has("Sleepycat")) add("Sleepycat");
    if (has("X Consortium")) add("X11");
    if (has("Creative Commons Attribution")) {
        bool sa = has("ShareAlike") || has("Share Alike");
        bool v4 = has("4.0");
        add(sa ? (v4 ? "CC-BY-SA-4.0" : "CC-BY-SA-3.0") : (v4 ? "CC-BY-4.0" : "CC-BY-3.0"));
    }
    // NCSA is BSD-3-form ("Redistribution and use ..." + "Neither the names"),
    // so recognize it first and suppress the generic BSD block below for it.
    bool ncsa = has("University of Illinois") && has("NCSA");
    if (ncsa) add("NCSA");
    // curl's "COPYRIGHT AND PERMISSION NOTICE" template is shared with c-ares/
    // libssh2 (which are MIT), so require the curl name to avoid mis-labeling.
    if (has("COPYRIGHT AND PERMISSION NOTICE") && has("curl")) add("curl");

    if (has("Permission is hereby granted, free of charge")) add("MIT");
    if (has("Permission to use, copy, modify, and/or distribute this software"))
        add("ISC");
    if (!ncsa && has("Redistribution and use in source and binary forms")) {
        if (has("All advertising materials mentioning")) add("BSD-4-Clause");
        else if (has("Neither the name")) add("BSD-3-Clause");
        else add("BSD-2-Clause");
    }
    if (has("Permission to use, copy, modify, and distribute this software and its documentation "
            "for any purpose, without fee, and without a written agreement"))
        add("PostgreSQL");
    if (has("altered source versions must be plainly marked")) add("Zlib");
    if (has("This is free and unencumbered software released into the public domain")) add("Unlicense");
    if (has("DO WHAT THE F")) add("WTFPL");  // "DO WHAT THE F*** YOU WANT TO PUBLIC LICENSE"
    if (has("CC0 1.0 Universal")) add("CC0-1.0");
    return out;
}

std::vector<Finding> scan_licenses(const std::string& relpath, std::span<const uint8_t> data) {
    std::vector<Finding> out;
    std::unordered_set<std::string> seen;  // dedup by license id within this file

    auto emit = [&](const std::string& id, Confidence conf, const std::string& ev, size_t off) {
        if (id.empty() || !seen.insert(id).second) return;
        Finding f;
        f.offset = off;
        f.type = id;
        f.category = "license";
        f.label = id;
        f.description = "License " + id + " (" + ev + ").";
        f.set_confidence(conf, ev);
        out.push_back(std::move(f));
    };

    // 1. SPDX-License-Identifier: tags anywhere in the content.
    std::string_view text = as_sv(data);
    const std::string tag = "SPDX-License-Identifier:";
    for (size_t p = text.find(tag); p != std::string_view::npos; p = text.find(tag, p + 1)) {
        size_t v = p + tag.size();
        while (v < text.size() && (text[v] == ' ' || text[v] == '\t')) ++v;
        // An SPDX expression is [A-Za-z0-9.-+()_: ] (ids + AND/OR/WITH + refs).
        // Stop at anything else — comment markers, XML entities (&#xA;), quotes.
        auto ok_spdx = [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == ' ' || c == '.' ||
                   c == '-' || c == '+' || c == '(' || c == ')' || c == ':' || c == '_';
        };
        size_t e = v;
        while (e < text.size() && ok_spdx(text[e])) ++e;
        std::string expr(text.substr(v, e - v));
        while (!expr.empty() && (expr.back() == ' ' || expr.back() == '\t')) expr.pop_back();
        if (!expr.empty() && expr.size() <= 128)
            emit(expr, Confidence::Validated, "SPDX-License-Identifier tag", p);
    }

    // 2. License-file text identification (basename or a license-named ancestor,
    //    so a decompressed NOTICE/LICENSE blob is matched too).
    if (is_license_path(relpath))
        for (const auto& id : identify_license_text(data))
            emit(id, Confidence::Structural, "license file text match", 0);

    return out;
}

}  // namespace ft
