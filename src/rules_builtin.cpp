#include "rules_builtin.hpp"

#include <algorithm>
#include <ctime>

#include "validators.hpp"

namespace ft {

namespace {

// --- matcher builders (all return a token length from the anchor offset) ---

// prefix already matched by the anchor; require exactly `body` chars of `pred`,
// and the following char must not continue the class (token boundary).
std::function<std::optional<Match>(const Reader&, size_t)> fixed(size_t prefix, size_t body,
                                                                 bool (*pred)(uint8_t)) {
    return [=](const Reader& r, size_t off) -> std::optional<Match> {
        if (run(r, off + prefix, body + 1, pred) != body) return std::nullopt;
        return Match{prefix + body, Confidence::Pattern, "", "", "", ""};
    };
}
// prefix matched; require at least `minbody` chars of `pred` (up to `maxbody`).
std::function<std::optional<Match>(const Reader&, size_t)> variable(size_t prefix, size_t minbody,
                                                                    size_t maxbody,
                                                                    bool (*pred)(uint8_t)) {
    return [=](const Reader& r, size_t off) -> std::optional<Match> {
        size_t n = run(r, off + prefix, maxbody, pred);
        if (n < minbody) return std::nullopt;
        return Match{prefix + n, Confidence::Pattern, "", "", "", ""};
    };
}

// GitHub classic token: prefix(4) + 36 base62; last 6 are a CRC32 checksum.
std::optional<Match> match_github_classic(const Reader& r, size_t off) {
    if (run(r, off + 4, 37, c_alnum) != 36) return std::nullopt;
    Match m;
    m.len = 40;
    std::string tok = token_str(r, off, 40);
    if (github_token_crc_ok(tok, 4)) {
        m.confidence = Confidence::Validated;
        m.evidence = "GitHub token, CRC32 checksum valid";
    } else {
        m.confidence = Confidence::Pattern;
        m.evidence = "GitHub token shape (checksum not matched)";
    }
    return m;
}

// JWT: three base64url segments; decode header/payload to read alg + exp.
std::optional<Match> match_jwt(const Reader& r, size_t off) {
    size_t a = run(r, off, 4096, c_base64url);
    if (a < 8) return std::nullopt;
    auto d1 = r.bytes(off + a, 1);
    if (!d1 || (*d1)[0] != '.') return std::nullopt;
    size_t b = run(r, off + a + 1, 4096, c_base64url);
    if (b < 8) return std::nullopt;
    auto d2 = r.bytes(off + a + 1 + b, 1);
    if (!d2 || (*d2)[0] != '.') return std::nullopt;
    size_t c = run(r, off + a + 1 + b + 1, 4096, c_base64url);
    size_t len = a + 1 + b + 1 + c;

    Match m;
    m.len = len;
    m.confidence = Confidence::Structural;
    m.evidence = "JWT structure (offline)";
    JwtInfo info = jwt_inspect(token_str(r, off, len), static_cast<long long>(std::time(nullptr)));
    if (info.ok) {
        std::string d = "JWT (alg=" + (info.alg.empty() ? std::string("?") : info.alg);
        if (info.exp > 0) d += info.expired ? ", expired" : ", unexpired";
        d += ")";
        m.description = d;
    }
    return m;
}

// PEM base64 body alphabet (standard, plus '=' padding). Newlines / whitespace
// are handled by the body scanner, not this predicate.
inline bool c_base64_pem(uint8_t c) { return c_alnum(c) || c == '+' || c == '/' || c == '='; }

// PEM private-key block: anchor "-----BEGIN "; parse the BEGIN header, then require
// three things a real key has and a library's embedded PEM label string does not
// (GH #26): (1) the header's own key type is a *private* key ("... PRIVATE KEY"),
// so a "PUBLIC KEY" / "CERTIFICATE" label is never reported as a private key;
// (2) a substantial base64 body follows the header; and (3) the block closes with
// the matching "-----END <same type>-----". Crypto libraries (mbedtls, OpenSSL,
// wolfSSL) embed the bare BEGIN/END label strings back to back in .rodata with no
// body between them; those must not be reported. The returned match length is the
// header line only (a marker, not secret bytes) -- the body scan is just a gate.
std::optional<Match> match_pem_private(const Reader& r, size_t off) {
    constexpr size_t PREFIX = 11;  // "-----BEGIN "
    const uint8_t* DASH5 = reinterpret_cast<const uint8_t*>("-----");

    // 1. Read the key-type token, from after "-----BEGIN " up to the closing
    //    "-----" of the header. Type words are uppercase letters and single spaces
    //    (e.g. "RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY").
    constexpr size_t MAX_TYPE = 40;
    size_t typelen = 0;
    for (; typelen <= MAX_TYPE; ++typelen) {
        auto b = r.bytes(off + PREFIX + typelen, 5);
        if (!b) return std::nullopt;
        if (std::equal(b->begin(), b->end(), DASH5)) break;
        uint8_t c = (*b)[0];
        if (!((c >= 'A' && c <= 'Z') || c == ' ')) return std::nullopt;
    }
    if (typelen == 0 || typelen > MAX_TYPE) return std::nullopt;
    std::string type = token_str(r, off + PREFIX, typelen);

    // 2. The header must itself be a PRIVATE KEY label (rejects PUBLIC KEY,
    //    CERTIFICATE, EC PARAMETERS, DH PARAMETERS, ...).
    const std::string PK = "PRIVATE KEY";
    if (type.size() < PK.size() || type.compare(type.size() - PK.size(), PK.size(), PK) != 0)
        return std::nullopt;

    const size_t hdr_end = off + PREFIX + typelen + 5;  // past "-----BEGIN <TYPE>-----"

    // 3. Require a real base64 body, then the matching "-----END <TYPE>-----".
    //    The first 5-dash run we meet must be that END and must be preceded by at
    //    least MIN_BODY base64 chars; otherwise (BEGIN immediately followed by an
    //    END/BEGIN, wrong END type, or no body) this is a bare label -> reject.
    const std::string end_marker = "-----END " + type + "-----";
    const auto* end_bytes = reinterpret_cast<const uint8_t*>(end_marker.data());
    constexpr size_t WINDOW = 1u << 16;  // 64 KiB: ample for any PEM key body
    constexpr size_t MIN_BODY = 64;      // smallest real key body is far larger than this
    size_t body_b64 = 0;
    bool closed = false;
    for (size_t p = hdr_end; p < hdr_end + WINDOW; ++p) {
        auto b = r.bytes(p, 5);
        if (!b) return std::nullopt;
        if (std::equal(b->begin(), b->end(), DASH5)) {
            if (body_b64 >= MIN_BODY &&
                r.matches_at(p, std::span<const uint8_t>(end_bytes, end_marker.size())))
                closed = true;
            break;  // first dash-run decides it: matching END with body, or reject
        }
        if (c_base64_pem((*b)[0])) ++body_b64;
    }
    if (!closed) return std::nullopt;

    Match m;
    m.len = PREFIX + typelen + 5;  // header line only; a marker, not secret bytes
    m.confidence = Confidence::Structural;
    std::string header = token_str(r, off, m.len);
    std::string kt = pem_key_type(header);
    m.label = header;
    m.evidence = "PEM private-key block (base64 body + matching END)";
    m.description = "Private key" + (kt.empty() ? std::string() : " (" + kt + ")");
    return m;
}

// Generic assignment: KEY <sep> <high-entropy value>. Noisy -> hard entropy gate
// applied by the engine (min_entropy on the rule).
std::optional<Match> match_generic(const Reader& r, size_t off) {
    size_t p = off;
    p += run(r, p, 32, c_alnum_us);  // the keyword
    size_t sep = 0;
    for (; sep < 6; ++sep) {
        auto b = r.bytes(p + sep, 1);
        if (!b) return std::nullopt;
        uint8_t c = (*b)[0];
        if (c == '=' || c == ':') { ++sep; break; }
        if (c != ' ' && c != '\t' && c != '"' && c != '\'') return std::nullopt;
    }
    p += sep;
    while (true) {
        auto b = r.bytes(p, 1);
        if (!b) break;
        uint8_t c = (*b)[0];
        if (c == ' ' || c == '"' || c == '\'') { ++p; continue; }
        break;
    }
    size_t v = run(r, p, 200, c_secretval);
    if (v < 16) return std::nullopt;
    return Match{(p + v) - off, Confidence::Pattern, "", "", "", ""};
}

std::vector<ContentRule> build_content_rules() {
    std::vector<ContentRule> d;
    auto add = [&](std::string type, std::vector<std::string> anchors,
                   std::function<std::optional<Match>(const Reader&, size_t)> m, double ent) {
        d.push_back(ContentRule{std::move(type), "secret", std::move(anchors), std::move(m), ent,
                                ""});
    };
    add("aws-access-key-id", {"AKIA", "ASIA"}, fixed(4, 16, c_base32u), 3.0);
    add("github-token", {"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, match_github_classic, 3.0);
    add("github-fine-grained-pat", {"github_pat_"}, variable(11, 60, 100, c_alnum_us), 3.0);
    add("gitlab-pat", {"glpat-"}, fixed(6, 20, c_base64url), 3.0);
    add("npm-token", {"npm_"}, fixed(4, 36, c_alnum), 3.0);
    add("slack-token", {"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxe-"},
        variable(5, 10, 100, c_base64url), 3.0);
    add("stripe-key", {"sk_live_", "rk_live_"}, variable(8, 20, 247, c_alnum), 3.0);
    add("sendgrid-key", {"SG."}, variable(3, 40, 90, c_base64url_dot), 3.5);
    add("openai-key", {"sk-proj-"}, variable(8, 20, 200, c_base64url), 3.5);
    add("anthropic-key", {"sk-ant-"}, variable(7, 20, 200, c_base64url), 3.5);
    add("google-api-key", {"AIza"}, fixed(4, 35, c_base64url), 3.0);
    add("google-oauth-token", {"ya29."}, variable(5, 20, 400, c_base64url), 3.5);
    add("jwt", {"eyJ"}, match_jwt, 3.5);
    add("private-key", {"-----BEGIN "}, match_pem_private, 0.0);
    add("generic-secret",
        {"password", "PASSWORD", "passwd", "secret", "SECRET", "api_key", "API_KEY", "apikey",
         "APIKEY", "access_token", "auth_token", "private_key"},
        match_generic, 3.5);
    return d;
}

std::vector<PathRule> build_path_rules() {
    std::vector<PathRule> p;
    auto add = [&](std::string glob, std::string cat, std::string type, std::string desc) {
        p.push_back(PathRule{std::move(glob), PathAction::FlagNotable, std::move(cat),
                             std::move(type), std::move(desc)});
    };
    add("**/shadow", "credential-file", "shadow-file", "Password hash database (/etc/shadow).");
    add("**/*.pem", "crypto", "pem-file", "PEM key/certificate file.");
    add("**/*.key", "crypto", "key-file", "Key file.");
    add("**/id_rsa", "crypto", "ssh-private-key", "SSH private key.");
    add("**/id_dsa", "crypto", "ssh-private-key", "SSH private key.");
    add("**/id_ecdsa", "crypto", "ssh-private-key", "SSH private key.");
    add("**/id_ed25519", "crypto", "ssh-private-key", "SSH private key.");
    add("**/*_host_key", "crypto", "ssh-host-key", "SSH/dropbear host key.");
    add("**/authorized_keys", "credential-file", "authorized-keys", "SSH authorized_keys.");
    add("**/.htpasswd", "credential-file", "htpasswd", "HTTP basic-auth password file.");
    add("**/htpasswd", "credential-file", "htpasswd", "HTTP basic-auth password file.");
    add("**/chap-secrets", "credential-file", "chap-secrets", "PPP CHAP secrets.");
    add("**/wpa_supplicant.conf", "config", "wifi-config", "Wi-Fi supplicant config (PSKs).");
    add("**/hostapd.conf", "config", "wifi-config", "Wi-Fi AP config (PSKs).");
    return p;
}

}  // namespace

const std::vector<ContentRule>& builtin_content_rules() {
    static const std::vector<ContentRule> rules = build_content_rules();
    return rules;
}

const std::vector<PathRule>& builtin_path_rules() {
    static const std::vector<PathRule> rules = build_path_rules();
    return rules;
}

}  // namespace ft
