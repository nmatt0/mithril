#include "langmanifest.hpp"

#include <cctype>
#include <functional>
#include <string_view>

#include "jsonparse.hpp"
#include "strutil.hpp"

namespace ft {

namespace {

std::string_view as_sv(std::span<const uint8_t> d) {
    return std::string_view(reinterpret_cast<const char*>(d.data()), d.size());
}

std::string_view trim(std::string_view s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '"' || s[a] == '\'')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '"' ||
                     s[b - 1] == '\''))
        --b;
    return s.substr(a, b - a);
}

Component mk(std::string source, std::string name, std::string version, std::string purl_type,
             const std::string& origin, uint8_t conf, std::string ev) {
    Component c;
    c.name = std::move(name);
    c.version = std::move(version);
    c.source = std::move(source);
    c.origin_path = origin;
    c.confidence = conf;
    c.evidence = std::move(ev);
    c.purl = "pkg:" + purl_type + "/" + c.name + (c.version.empty() ? "" : "@" + c.version);
    return c;
}

template <class F>
void for_each_line(std::string_view text, F cb) {
    size_t start = 0;
    while (start <= text.size()) {
        size_t nl = text.find('\n', start);
        cb(text.substr(start, nl == std::string_view::npos ? std::string_view::npos : nl - start));
        if (nl == std::string_view::npos) break;
        start = nl + 1;
    }
}

// --- npm: package-lock.json (v2/v3 "packages", or v1 "dependencies") ---
void parse_package_lock(std::span<const uint8_t> data, const std::string& origin,
                        std::vector<Component>& out) {
    auto doc = json_parse(as_sv(data));
    if (!doc || !doc->is_object()) return;

    if (const JsonValue* pkgs = doc->find("packages"); pkgs && pkgs->is_object()) {
        for (const auto& m : pkgs->obj) {
            if (m.key.empty()) continue;  // "" is the root project
            size_t nm = m.key.rfind("node_modules/");
            std::string name = nm == std::string::npos ? m.key : m.key.substr(nm + 13);
            std::string ver = m.value.get_str("version");
            if (!name.empty() && !ver.empty())
                out.push_back(mk("npm", name, ver, "npm", origin, 85, "npm package-lock"));
        }
        return;
    }
    // v1: recursive "dependencies": { name: {version, dependencies:{...}} }
    std::function<void(const JsonValue&)> rec = [&](const JsonValue& node) {
        const JsonValue* deps = node.find("dependencies");
        if (!deps || !deps->is_object()) return;
        for (const auto& m : deps->obj) {
            std::string ver = m.value.get_str("version");
            if (!m.key.empty() && !ver.empty())
                out.push_back(mk("npm", m.key, ver, "npm", origin, 85, "npm package-lock"));
            rec(m.value);
        }
    };
    rec(*doc);
}

// --- pypi: requirements.txt (exact "name==version" pins only) ---
void parse_requirements(std::span<const uint8_t> data, const std::string& origin,
                        std::vector<Component>& out) {
    for_each_line(as_sv(data), [&](std::string_view line) {
        std::string_view l = trim(line);
        if (l.empty() || l[0] == '#' || l[0] == '-') return;
        size_t eq = l.find("==");
        if (eq == std::string_view::npos) return;
        std::string name(trim(l.substr(0, eq)));
        std::string_view rest = l.substr(eq + 2);
        // stop version at whitespace, ';' (env marker), or a trailing comment
        size_t end = 0;
        while (end < rest.size() && rest[end] != ' ' && rest[end] != ';' && rest[end] != '#' &&
               rest[end] != '\t')
            ++end;
        std::string ver(trim(rest.substr(0, end)));
        // strip a leading '=' (===)
        while (!ver.empty() && ver.front() == '=') ver.erase(ver.begin());
        if (!name.empty() && !ver.empty())
            out.push_back(mk("pypi", name, ver, "pypi", origin, 80, "requirements.txt pin"));
    });
}

// --- pypi: PKG-INFO / METADATA (deb822-ish "Name:" + "Version:") ---
void parse_pkginfo(std::span<const uint8_t> data, const std::string& origin,
                   std::vector<Component>& out) {
    std::string name, version;
    for_each_line(as_sv(data), [&](std::string_view line) {
        if (line.rfind("Name:", 0) == 0) name = std::string(trim(line.substr(5)));
        else if (line.rfind("Version:", 0) == 0) version = std::string(trim(line.substr(8)));
    });
    if (!name.empty() && !version.empty())
        out.push_back(mk("pypi", name, version, "pypi", origin, 85, "python PKG-INFO/METADATA"));
}

// --- go: go.mod ("require" directives) ---
void parse_go_mod(std::span<const uint8_t> data, const std::string& origin,
                  std::vector<Component>& out) {
    bool in_block = false;
    for_each_line(as_sv(data), [&](std::string_view line) {
        std::string_view l = trim(line);
        if (l.rfind("require (", 0) == 0) { in_block = true; return; }
        if (in_block && l == ")") { in_block = false; return; }
        std::string_view r = l;
        if (!in_block) {
            if (r.rfind("require ", 0) != 0) return;
            r = trim(r.substr(8));
        }
        if (r.empty() || r[0] == '/') return;  // comment
        size_t sp = r.find(' ');
        if (sp == std::string_view::npos) return;
        std::string mod(trim(r.substr(0, sp)));
        std::string ver(trim(r.substr(sp + 1)));
        // drop "// indirect" trailer
        if (size_t c = ver.find("//"); c != std::string::npos) ver = std::string(trim(ver.substr(0, c)));
        if (!mod.empty() && !ver.empty())
            out.push_back(mk("golang", mod, ver, "golang", origin, 85, "go.mod require"));
    });
}

// --- cargo: Cargo.lock ([[package]] name/version) ---
void parse_cargo_lock(std::span<const uint8_t> data, const std::string& origin,
                      std::vector<Component>& out) {
    std::string name, version;
    bool in_pkg = false;
    auto flush = [&] {
        if (in_pkg && !name.empty() && !version.empty())
            out.push_back(mk("cargo", name, version, "cargo", origin, 85, "Cargo.lock"));
        name.clear();
        version.clear();
    };
    for_each_line(as_sv(data), [&](std::string_view line) {
        std::string_view l = trim(line);
        if (l == "[[package]]") { flush(); in_pkg = true; return; }
        if (!l.empty() && l[0] == '[') { flush(); in_pkg = false; return; }
        if (!in_pkg) return;
        if (l.rfind("name = ", 0) == 0) name = std::string(trim(l.substr(7)));
        else if (l.rfind("version = ", 0) == 0) version = std::string(trim(l.substr(10)));
    });
    flush();
}

// --- php: composer.lock (JSON "packages":[{name,version}]) ---
void parse_composer_lock(std::span<const uint8_t> data, const std::string& origin,
                         std::vector<Component>& out) {
    auto doc = json_parse(as_sv(data));
    if (!doc || !doc->is_object()) return;
    for (const char* key : {"packages", "packages-dev"}) {
        const JsonValue* arr = doc->find(key);
        if (!arr || !arr->is_array()) continue;
        for (const JsonValue& p : arr->arr) {
            std::string name = p.get_str("name"), ver = p.get_str("version");
            // composer versions often carry a leading 'v'
            if (!ver.empty() && ver[0] == 'v') ver.erase(ver.begin());
            if (!name.empty() && !ver.empty())
                out.push_back(mk("composer", name, ver, "composer", origin, 85, "composer.lock"));
        }
    }
}

// --- ruby: Gemfile.lock (GEM specs: "  name (version)") ---
void parse_gemfile_lock(std::span<const uint8_t> data, const std::string& origin,
                        std::vector<Component>& out) {
    bool in_specs = false;
    for_each_line(as_sv(data), [&](std::string_view line) {
        // section headers are unindented; specs entries are indented 4 spaces
        if (!line.empty() && line[0] != ' ') {
            in_specs = (line.rfind("GEM", 0) == 0);
            return;
        }
        std::string_view l = trim(line);
        if (l.rfind("specs:", 0) == 0) return;
        if (!in_specs) return;
        // "name (version)" — exactly the direct gems have this shape
        size_t paren = l.find(" (");
        if (paren == std::string_view::npos || l.back() != ')') return;
        std::string name(trim(l.substr(0, paren)));
        std::string ver(l.substr(paren + 2, l.size() - paren - 3));
        if (!name.empty() && !ver.empty() && ver.find_first_of("<>=~") == std::string::npos)
            out.push_back(mk("gem", name, ver, "gem", origin, 80, "Gemfile.lock"));
    });
}

}  // namespace

std::vector<Component> scan_langmanifest(const std::string& relpath, std::span<const uint8_t> data) {
    std::string_view base = basename_of(relpath);
    std::vector<Component> out;
    if (base == "package-lock.json" || base == "npm-shrinkwrap.json")
        parse_package_lock(data, relpath, out);
    else if (base == "requirements.txt")
        parse_requirements(data, relpath, out);
    else if (base == "PKG-INFO" || base == "METADATA")
        parse_pkginfo(data, relpath, out);
    else if (base == "go.mod")
        parse_go_mod(data, relpath, out);
    else if (base == "Cargo.lock")
        parse_cargo_lock(data, relpath, out);
    else if (base == "composer.lock")
        parse_composer_lock(data, relpath, out);
    else if (base == "Gemfile.lock")
        parse_gemfile_lock(data, relpath, out);
    return out;
}

}  // namespace ft
