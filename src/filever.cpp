#include "filever.hpp"

#include <regex>
#include <string_view>

#include "strutil.hpp"

namespace ft {

namespace {

// A versioned-filename signature: the basename regex (capture group 1 = version),
// the component name, and its CPE vendor/product.
struct FileSig {
    std::string pattern;
    std::string name;
    std::string cpe_vendor;
    std::string cpe_product;
};

const std::vector<FileSig>& sigs() {
    static const std::vector<FileSig> s = {
        // uClibc: libuClibc-0.9.33.2.so / ld-uClibc-1.0.31.so
        {R"((?:lib|ld-)uClibc-(\d+\.\d+(?:\.\d+){0,2})\.so)", "uclibc", "uclibc", "uclibc"},
        // glibc: libc-2.31.so / ld-2.25.so (the standard glibc soname file)
        {R"((?:libc|ld)-(\d+\.\d+(?:\.\d+)?)\.so)", "glibc", "gnu", "glibc"},
    };
    return s;
}

const std::vector<std::regex>& compiled() {
    static const std::vector<std::regex> re = [] {
        std::vector<std::regex> v;
        for (const auto& s : sigs())
            v.emplace_back(s.pattern, std::regex::ECMAScript | std::regex::optimize);
        return v;
    }();
    return re;
}

}  // namespace

std::vector<Component> scan_filename_version(const std::string& relpath) {
    std::vector<Component> out;
    std::string base(basename_of(relpath));
    const auto& S = sigs();
    const auto& RE = compiled();
    for (size_t i = 0; i < S.size(); ++i) {
        std::smatch m;
        if (!std::regex_match(base, m, RE[i]) || m.size() < 2) continue;
        std::string version = m[1].str();
        Component c;
        c.name = S[i].name;
        c.version = version;
        c.purl = "pkg:generic/" + c.name + "@" + version;
        c.cpe = "cpe:2.3:a:" + S[i].cpe_vendor + ":" + S[i].cpe_product + ":" + version +
                ":*:*:*:*:*:*:*";
        c.source = "filename";
        c.origin_path = relpath;
        c.confidence = 80;  // the filename is a reliable but not authoritative version
        c.evidence = "versioned library filename: " + base;
        out.push_back(std::move(c));
        break;  // one component per file
    }
    return out;
}

std::vector<std::pair<std::string, std::string>> filever_cpe_products() {
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& s : sigs())
        if (!s.cpe_vendor.empty()) out.push_back({s.cpe_vendor, s.cpe_product});
    return out;
}

}  // namespace ft
