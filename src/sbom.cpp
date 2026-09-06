#include "sbom.hpp"

#include <string_view>

#include "strutil.hpp"

namespace ft {

namespace {

std::string_view as_sv(std::span<const uint8_t> d) {
    return std::string_view(reinterpret_cast<const char*>(d.data()), d.size());
}

bool contains(std::string_view hay, std::string_view needle) {
    return hay.find(needle) != std::string_view::npos;
}
bool ends_with(std::string_view s, std::string_view suf) {
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

std::string_view trim(std::string_view s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r')) --b;
    return s.substr(a, b - a);
}

// Call cb(line) for each newline-delimited line (without the newline).
template <class F>
void for_each_line(std::string_view text, F cb) {
    size_t start = 0;
    while (start <= text.size()) {
        size_t nl = text.find('\n', start);
        std::string_view line =
            text.substr(start, nl == std::string_view::npos ? std::string_view::npos : nl - start);
        cb(line);
        if (nl == std::string_view::npos) break;
        start = nl + 1;
    }
}

std::string make_purl(const std::string& source, const std::string& name, const std::string& version,
                      const std::string& arch) {
    std::string ptype = "generic", ns;
    if (source == "dpkg") {
        ptype = "deb";
    } else if (source == "opkg") {
        ptype = "opkg";
    } else if (source == "apk") {
        ptype = "apk";
        ns = "alpine";
    }
    std::string purl = "pkg:" + ptype + "/";
    if (!ns.empty()) purl += ns + "/";
    purl += name;
    if (!version.empty()) purl += "@" + version;
    if (!arch.empty()) purl += "?arch=" + arch;
    return purl;
}

}  // namespace

std::vector<Component> parse_deb822_status(std::span<const uint8_t> data, const std::string& source,
                                           const std::string& origin_path) {
    std::vector<Component> out;
    std::string name, version, arch, status;

    // The install state is the final token of Status ("<want> <error> <state>"):
    // "install ok installed" / "install user installed" are installed;
    // "purge ok not-installed" / "deinstall ok config-files" are not.
    auto is_installed = [](const std::string& st) {
        size_t sp = st.find_last_of(" \t");
        std::string_view last = sp == std::string::npos ? std::string_view(st)
                                                        : std::string_view(st).substr(sp + 1);
        return last == "installed";
    };

    auto flush = [&] {
        if (!name.empty() && !version.empty() && is_installed(status)) {
            Component c;
            c.name = name;
            c.version = version;
            c.arch = arch;
            c.source = source;
            c.origin_path = origin_path;
            c.purl = make_purl(source, name, version, arch);
            c.confidence = 95;
            c.evidence = source + " status: " + (status.empty() ? "installed" : status);
            out.push_back(std::move(c));
        }
        name.clear();
        version.clear();
        arch.clear();
        status.clear();
    };

    for_each_line(as_sv(data), [&](std::string_view line) {
        if (line.empty() || line == "\r") {  // stanza boundary
            flush();
            return;
        }
        if (line[0] == ' ' || line[0] == '\t') return;  // continuation of a multi-line field
        size_t colon = line.find(':');
        if (colon == std::string_view::npos) return;
        std::string_view key = line.substr(0, colon);
        std::string_view val = trim(line.substr(colon + 1));
        if (key == "Package") name = std::string(val);
        else if (key == "Version") version = std::string(val);
        else if (key == "Architecture") arch = std::string(val);
        else if (key == "Status") status = std::string(val);
    });
    flush();  // last stanza (file may not end with a blank line)
    return out;
}

std::vector<Component> parse_apk_installed(std::span<const uint8_t> data,
                                           const std::string& origin_path) {
    std::vector<Component> out;
    std::string name, version, arch, license;

    auto flush = [&] {
        if (!name.empty() && !version.empty()) {
            Component c;
            c.name = name;
            c.version = version;
            c.arch = arch;
            c.license = license;
            c.source = "apk";
            c.origin_path = origin_path;
            c.purl = make_purl("apk", name, version, arch);
            c.confidence = 95;
            c.evidence = "apk installed database entry";
            out.push_back(std::move(c));
        }
        name.clear();
        version.clear();
        arch.clear();
        license.clear();
    };

    for_each_line(as_sv(data), [&](std::string_view line) {
        if (line.empty() || line == "\r") {
            flush();
            return;
        }
        if (line.size() < 2 || line[1] != ':') return;  // apk lines are "K:value"
        char key = line[0];
        std::string_view val = trim(line.substr(2));
        switch (key) {
            case 'P': name = std::string(val); break;
            case 'V': version = std::string(val); break;
            case 'A': arch = std::string(val); break;
            case 'L': license = std::string(val); break;
            default: break;
        }
    });
    flush();
    return out;
}

std::vector<Component> scan_sbom(const std::string& relpath, std::span<const uint8_t> data) {
    std::string_view p = relpath;
    std::string_view base = basename_of(p);

    if (contains(p, "dpkg/status") || (base == "status" && !contains(p, "opkg")))
        return parse_deb822_status(data, "dpkg", relpath);
    if (contains(p, "opkg/status"))
        return parse_deb822_status(data, "opkg", relpath);
    if (contains(p, "apk/db/installed") || base == "installed")
        return parse_apk_installed(data, relpath);
    (void)ends_with;  // reserved for future manifest suffix matching
    return {};
}

}  // namespace ft
