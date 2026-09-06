#include "credstore.hpp"

#include <cctype>
#include <string_view>

#include "strutil.hpp"

namespace ft {

namespace {

std::string_view as_sv(std::span<const uint8_t> d) {
    return std::string_view(reinterpret_cast<const char*>(d.data()), d.size());
}

bool starts_with(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

// Classify a crypt(3)-style hash. `weak` marks algorithms that are trivially or
// cheaply crackable (unsalted, fast, or broken) and should be called out.
struct CryptAlgo {
    std::string name;
    bool weak = false;
    bool known = false;
};

CryptAlgo classify(std::string_view h) {
    auto A = [](const char* n, bool weak) { return CryptAlgo{n, weak, true}; };
    if (starts_with(h, "$1$")) return A("md5crypt", true);
    if (starts_with(h, "$apr1$")) return A("apr1-md5", true);
    if (starts_with(h, "$2a$") || starts_with(h, "$2b$") || starts_with(h, "$2y$"))
        return A("bcrypt", false);
    if (starts_with(h, "$5$")) return A("sha256crypt", false);
    if (starts_with(h, "$6$")) return A("sha512crypt", false);
    if (starts_with(h, "$7$")) return A("scrypt", false);
    if (starts_with(h, "$y$")) return A("yescrypt", false);
    if (starts_with(h, "$gy$")) return A("gost-yescrypt", false);
    if (starts_with(h, "{SHA}")) return A("sha1-base64", true);
    // Traditional DES crypt: exactly 13 chars from the crypt alphabet, no '$'.
    if (h.size() == 13 && h.find('$') == std::string_view::npos) {
        bool ok = true;
        for (char c : h)
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '/')) ok = false;
        if (ok) return A("descrypt", true);
    }
    return CryptAlgo{};  // not a recognized hash
}

// Iterate lines with their starting byte offset.
template <class F>
void for_each_line(std::string_view text, F cb) {
    size_t start = 0;
    while (start <= text.size()) {
        size_t nl = text.find('\n', start);
        std::string_view line =
            text.substr(start, nl == std::string_view::npos ? std::string_view::npos : nl - start);
        cb(start, line);
        if (nl == std::string_view::npos) break;
        start = nl + 1;
    }
}

Finding make_hash_finding(std::string_view user, const CryptAlgo& algo, const std::string& type,
                          size_t offset) {
    Finding f;
    f.offset = offset;
    f.type = type;
    f.category = "secret";
    f.label = std::string(user) + " (" + algo.name + ")";
    f.description = std::string(algo.weak ? "Weak " : "") + algo.name + " password hash for '" +
                    std::string(user) + "'" + (algo.weak ? " (cheaply crackable)." : ".");
    f.set_confidence(Confidence::Validated,
                     algo.weak ? "weak crypt hash (" + algo.name + ")" : "crypt hash (" + algo.name + ")");
    return f;
}

}  // namespace

std::vector<Finding> parse_shadow(std::span<const uint8_t> data, const std::string& origin) {
    (void)origin;
    std::vector<Finding> out;
    for_each_line(as_sv(data), [&](size_t off, std::string_view line) {
        if (line.empty() || line[0] == '#') return;
        size_t c1 = line.find(':');
        if (c1 == std::string_view::npos) return;
        std::string_view user = line.substr(0, c1);
        std::string_view rest = line.substr(c1 + 1);
        size_t c2 = rest.find(':');
        std::string_view hash = (c2 == std::string_view::npos) ? rest : rest.substr(0, c2);
        if (user.empty()) return;

        if (hash.empty()) {
            Finding f;
            f.offset = off;
            f.type = "empty-password";
            f.category = "secret";
            f.label = std::string(user);
            f.description = "Account '" + std::string(user) + "' has an empty password.";
            f.set_confidence(Confidence::Validated, "empty password field");
            out.push_back(std::move(f));
            return;
        }
        // Locked / disabled accounts (*, !, !!, !<hash>) carry no usable secret.
        if (hash[0] == '*' || hash[0] == '!') return;

        CryptAlgo algo = classify(hash);
        if (!algo.known) return;
        out.push_back(make_hash_finding(user, algo, "password-hash", off + c1 + 1));
    });
    return out;
}

std::vector<Finding> parse_htpasswd(std::span<const uint8_t> data, const std::string& origin) {
    (void)origin;
    std::vector<Finding> out;
    for_each_line(as_sv(data), [&](size_t off, std::string_view line) {
        if (line.empty() || line[0] == '#') return;
        size_t c1 = line.find(':');
        if (c1 == std::string_view::npos) return;
        std::string_view user = line.substr(0, c1);
        std::string_view hash = line.substr(c1 + 1);
        if (user.empty() || hash.empty()) return;
        CryptAlgo algo = classify(hash);
        if (!algo.known) return;
        out.push_back(make_hash_finding(user, algo, "htpasswd-hash", off + c1 + 1));
    });
    return out;
}

std::vector<Finding> scan_credstores(const std::string& relpath, std::span<const uint8_t> data) {
    std::string_view base = basename_of(relpath);
    if (base == "shadow") return parse_shadow(data, relpath);
    if (base == "htpasswd" || base == ".htpasswd") return parse_htpasswd(data, relpath);
    return {};
}

}  // namespace ft
