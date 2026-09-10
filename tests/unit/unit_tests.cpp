// unit_tests.cpp — direct tests of mithril's engine + primitives. No framework:
// a CHECK macro + main. Built as `mithril_unit`.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "ahocorasick.hpp"
#include "binver.hpp"
#include "component.hpp"
#include "credstore.hpp"
#include "derkey.hpp"
#include "cve.hpp"
#include "osvindex.hpp"
#include "sha256.hpp"
#include "engine.hpp"
#include "entropy.hpp"
#include "filever.hpp"
#include "finding.hpp"
#include "inflate.hpp"
#include "jsonparse.hpp"
#include "kallsyms.hpp"
#include "kconfig_infer.hpp"
#include "kernelcve.hpp"
#include "langmanifest.hpp"
#include "license.hpp"
#include "reader.hpp"
#include "rpm.hpp"
#include "rule.hpp"
#include "rules_builtin.hpp"
#include "sbom.hpp"
#include "sbom_emit.hpp"
#include "userrules.hpp"
#include "validators.hpp"
#include "version.hpp"

static int g_checks = 0, g_fails = 0;
#define CHECK(cond)                                                        \
    do {                                                                   \
        ++g_checks;                                                        \
        if (!(cond)) {                                                     \
            ++g_fails;                                                     \
            std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);  \
        }                                                                  \
    } while (0)

// ---------------------------------------------------------------- helpers
static const ft::Engine& engine() {
    static ft::Engine e(ft::builtin_content_rules(), ft::builtin_path_rules());
    return e;
}
static std::vector<ft::Finding> scan(const std::string& s) {
    ft::Reader r(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()), s.size()));
    return engine().scan_content(r);
}
static const ft::Finding* find_type(const std::vector<ft::Finding>& fs, const std::string& t) {
    for (const auto& f : fs)
        if (f.type == t) return &f;
    return nullptr;
}
static bool has_type(const std::vector<ft::Finding>& fs, const std::string& t) {
    return find_type(fs, t) != nullptr;
}

static std::string b64(const std::string& in) {
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o;
    int val = 0, bits = 0;
    for (unsigned char c : in) {
        val = (val << 8) | c;
        bits += 8;
        while (bits >= 6) { bits -= 6; o += T[(val >> bits) & 0x3F]; }
    }
    if (bits) o += T[(val << (6 - bits)) & 0x3F];
    while (o.size() % 4) o += '=';
    return o;
}

// ---------------------------------------------------------------- ahocorasick
static void test_ahocorasick() {
    ft::AhoCorasick ac;
    ac.add({'A', 'K', 'I', 'A'}, 0);
    ac.add({'g', 'h', 'p', '_'}, 1);
    ac.build();
    std::string data = "xx AKIA yy ghp_ zz AKIA";
    std::vector<std::pair<size_t, uint32_t>> hits;
    ac.find(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(data.data()), data.size()), 0,
            [&](size_t off, uint32_t id) { hits.push_back({off, id}); return true; });
    CHECK(hits.size() == 3);
    CHECK(hits[0].first == 3 && hits[0].second == 0);
    CHECK(hits[1].second == 1);
}

// ---------------------------------------------------------------- entropy
static void test_entropy() {
    std::string uniform(256, 'A');
    CHECK(ft::string_entropy(std::span<const uint8_t>(
              reinterpret_cast<const uint8_t*>(uniform.data()), uniform.size())) < 0.01);
    CHECK(ft::token_entropy("AKIAJ2K3L4M5N6P7Q8R9") > 3.0);
}

// ---------------------------------------------------------------- json parser
static void test_jsonparse() {
    auto v = ft::json_parse(R"({"a":1,"b":"x","c":true,"d":[1,2,3],"e":{"f":null}})");
    CHECK(v.has_value());
    if (v) {
        CHECK(v->get_num("a") == 1.0);
        CHECK(v->get_str("b") == "x");
        CHECK(v->get_bool("c") == true);
        const ft::JsonValue* d = v->find("d");
        CHECK(d && d->is_array() && d->arr.size() == 3);
    }
    auto s = ft::json_parse(R"("a\tbA\n")");
    CHECK(s.has_value() && s->is_string() && s->str == "a\tbA\n");
    CHECK(!ft::json_parse("{").has_value());
    CHECK(!ft::json_parse("{} x").has_value());

    // Depth guard: deep nesting is rejected as malformed rather than overflowing
    // the stack (a crafted lockfile/JWT/feed must not crash the parser).
    auto deep = [](int n) {
        return std::string(n, '[') + std::string(n, ']');
    };
    CHECK(ft::json_parse(deep(64)).has_value());     // well within the cap
    CHECK(!ft::json_parse(deep(100000)).has_value()); // pathological -> nullopt, no crash
    // Deep nesting inside an object value is rejected too (the JWT/lockfile shape).
    CHECK(!ft::json_parse("{\"a\":" + deep(100000) + "}").has_value());
}

// ---------------------------------------------------------------- detectors
static void test_detectors() {
    CHECK(has_type(scan("cfg AWS=AKIAJ2K3L4M5N6P7Q8R9 end"), "aws-access-key-id"));
    CHECK(has_type(scan("t=github_pat_11ABCDE0123456789_abcdefGHIJKLMNOPqrstuvwx0123456789ABCDEFGH\n"),
                   "github-fine-grained-pat"));
    // Literals split so secret scanners don't flag these synthetic fixtures; adjacent
    // string-literal concatenation makes the scanned value byte-identical at compile time.
    CHECK(has_type(scan("glpat-" "AbCdEf0123456789xYzQ end"), "gitlab-pat"));
    CHECK(has_type(scan("k=sk_live_" "0123456789abcdefABCDEF01 end"), "stripe-key"));
    CHECK(has_type(scan("key AIzaabcdefghijklmnopqrstuvwxyz012345678 x"), "google-api-key"));
    CHECK(has_type(scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n"), "private-key"));
    CHECK(has_type(scan("password = s3cr3tP@ssw0rd_9xQ7zLmN end"), "generic-secret"));
}

static void test_false_positives() {
    CHECK(!has_type(scan("AKIAIOSFODNN7EXAMPLE"), "aws-access-key-id"));
    CHECK(!has_type(scan("password = your_password_here_xx"), "generic-secret"));
    CHECK(scan("The quick brown fox jumps over the lazy dog near the river.").empty());
    CHECK(!has_type(scan("secret = abc"), "generic-secret"));
}

static void test_encoded() {
    std::string enc = b64("cred AKIAJ2K3L4M5N6P7Q8R9 tail");
    auto fs = scan("data: " + enc + " done");
    bool found = false;
    for (const auto& f : fs)
        if (f.type == "aws-access-key-id" && f.evidence.find("base64") != std::string::npos)
            found = true;
    CHECK(found);

    std::string tok = "AKIAJ2K3L4M5N6P7Q8R9", wide;
    for (char c : tok) { wide += c; wide += '\0'; }
    auto fs2 = scan("hdr" + wide + "hdr");
    bool found2 = false;
    for (const auto& f : fs2)
        if (f.type == "aws-access-key-id" && f.evidence.find("utf16le") != std::string::npos)
            found2 = true;
    CHECK(found2);
}

// ---------------------------------------------------------------- confidence ladder
static void test_validators_github_crc() {
    // Build a checksum-valid classic token: ghp_ + 30 body + 6 base62(CRC32(body)).
    std::string body = "abcdefghijklmnopqrstuvwxyz0123";  // 30 base62 chars
    CHECK(body.size() == 30);
    std::string checksum = ft::base62_crc32_6(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(body.data()), body.size()));
    CHECK(checksum.size() == 6);
    std::string token = "ghp_" + body + checksum;  // 40 chars
    CHECK(ft::github_token_crc_ok(token, 4));

    // Flip a body char: checksum must no longer validate.
    std::string bad = token;
    bad[5] = (bad[5] == 'z') ? 'y' : 'z';
    CHECK(!ft::github_token_crc_ok(bad, 4));

    // Through the engine: valid checksum -> validated tier; still detected either way.
    auto good = scan("token: " + token + "\n");
    const ft::Finding* g = find_type(good, "github-token");
    CHECK(g && g->confidence == static_cast<uint8_t>(ft::Confidence::Validated));
    auto worse = scan("token: " + bad + "\n");
    const ft::Finding* w = find_type(worse, "github-token");
    CHECK(w && w->confidence == static_cast<uint8_t>(ft::Confidence::Pattern));
}

static void test_validators_jwt() {
    // Classic jwt.io HS256 example (no exp claim).
    std::string jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    ft::JwtInfo info = ft::jwt_inspect(jwt, 0);
    CHECK(info.ok);
    CHECK(info.alg == "HS256");

    auto fs = scan("Authorization: Bearer " + jwt + "\n");
    const ft::Finding* f = find_type(fs, "jwt");
    CHECK(f && f->confidence == static_cast<uint8_t>(ft::Confidence::Structural));
}

static void test_validators_pem() {
    CHECK(ft::pem_key_type("-----BEGIN RSA PRIVATE KEY-----") == "RSA");
    CHECK(ft::pem_key_type("-----BEGIN OPENSSH PRIVATE KEY-----") == "OPENSSH");
    CHECK(ft::pem_key_type("-----BEGIN PRIVATE KEY-----") == "");
    auto fs = scan("-----BEGIN EC PRIVATE KEY-----\nMHc...\n");
    const ft::Finding* f = find_type(fs, "private-key");
    CHECK(f && f->confidence == static_cast<uint8_t>(ft::Confidence::Structural));
    CHECK(f && f->description.find("EC") != std::string::npos);
}

// ---------------------------------------------------------------- glob + path rules
static void test_glob() {
    CHECK(ft::glob_match("**/shadow", "etc/shadow"));
    CHECK(ft::glob_match("**/shadow", "shadow"));
    CHECK(ft::glob_match("**/*.pem", "etc/ssl/server.pem"));
    CHECK(!ft::glob_match("**/*.pem", "etc/ssl/server.crt"));
    CHECK(ft::glob_match("**/id_rsa", "home/root/.ssh/id_rsa"));
    CHECK(ft::glob_match("*.conf", "hostapd.conf"));
    CHECK(!ft::glob_match("*.conf", "etc/hostapd.conf"));  // '*' does not cross '/'
    CHECK(ft::glob_match("a/?/c", "a/b/c"));
    CHECK(!ft::glob_match("a/?/c", "a/bb/c"));
}

static void test_path_rules() {
    auto sh = engine().scan_paths("etc/shadow", 123);
    CHECK(sh.size() == 1 && sh[0].type == "shadow-file" && sh[0].category == "credential-file");
    CHECK(sh.size() == 1 && sh[0].size == 123);
    auto rsa = engine().scan_paths("home/root/.ssh/id_rsa", 0);
    CHECK(rsa.size() == 1 && rsa[0].type == "ssh-private-key");
    CHECK(engine().scan_paths("app/src/main.c", 0).empty());
}

// ---------------------------------------------------------------- metadata
static void test_metadata() {
    auto fs = scan("AWS=AKIAJ2K3L4M5N6P7Q8R9");
    CHECK(!fs.empty());
    if (!fs.empty()) {
        const ft::Finding& f = fs[0];
        CHECK(f.category == "secret");
        CHECK(f.confidence > 0);
        CHECK(f.label.find("...") != std::string::npos);
    }
}

// ---------------------------------------------------------------- sbom parsers
static std::vector<ft::Component> sbom(const std::string& relpath, const std::string& content) {
    return ft::scan_sbom(relpath, std::span<const uint8_t>(
                                      reinterpret_cast<const uint8_t*>(content.data()),
                                      content.size()));
}
static const ft::Component* find_comp(const std::vector<ft::Component>& cs, const std::string& n) {
    for (const auto& c : cs)
        if (c.name == n) return &c;
    return nullptr;
}

static void test_sbom_dpkg() {
    std::string status =
        "Package: busybox\nStatus: install ok installed\nVersion: 1:1.30.1-6\nArchitecture: armhf\n\n"
        "Package: removed-pkg\nStatus: deinstall ok config-files\nVersion: 2.0\n\n"
        "Package: purged-pkg\nStatus: purge ok not-installed\nVersion: 3.0\n\n"
        "Package: dropbear\nStatus: install ok installed\nVersion: 2019.78-2\nArchitecture: armhf\n";
    auto cs = sbom("var/lib/dpkg/status", status);
    CHECK(cs.size() == 2);
    CHECK(find_comp(cs, "purged-pkg") == nullptr);
    const ft::Component* bb = find_comp(cs, "busybox");
    CHECK(bb && bb->purl == "pkg:deb/busybox@1:1.30.1-6?arch=armhf");
}

static void test_sbom_opkg() {
    auto cs = sbom("usr/lib/opkg/status",
                   "Package: dnsmasq\nVersion: 2.80-5\nStatus: install user installed\n"
                   "Architecture: mipsel_24kc\n");
    CHECK(cs.size() == 1 && cs[0].purl == "pkg:opkg/dnsmasq@2.80-5?arch=mipsel_24kc");
}

static void test_sbom_apk() {
    auto cs = sbom("lib/apk/db/installed",
                   "P:musl\nV:1.2.4-r2\nA:x86_64\nL:MIT\n\nP:busybox\nV:1.36.1-r5\nA:x86_64\n");
    CHECK(cs.size() == 2);
    const ft::Component* m = find_comp(cs, "musl");
    CHECK(m && m->license == "MIT" && m->purl == "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64");
}

// ---------------------------------------------------------------- credential stores
static std::vector<ft::Finding> cred(const std::string& relpath, const std::string& content) {
    return ft::scan_credstores(relpath, std::span<const uint8_t>(
                                            reinterpret_cast<const uint8_t*>(content.data()),
                                            content.size()));
}

static void test_credstore_shadow() {
    std::string shadow =
        "root:$6$salt$aaaaaaaaaaaaaaaaaaaa:19000:0:99999:7:::\n"  // sha512, ok
        "admin:$1$abc$0123456789abcdefghijkl:19000:0:::\n"        // md5crypt, weak
        "legacy:abcdefghij123:19000:0:::\n"                       // descrypt (13ch), weak
        "guest::19000:0:::\n"                                     // empty password
        "locked:!:19000:0:::\n"                                   // locked, skip
        "daemon:*:19000:0:::\n"                                   // disabled, skip
        "bin:x:19000:0:::\n";                                     // not a hash, skip
    auto fs = cred("etc/shadow", shadow);
    CHECK(fs.size() == 4);
    const ft::Finding* root = find_type(fs, "password-hash");  // first is root
    CHECK(root != nullptr);
    // Collect by user-in-label for precise checks.
    auto by_user = [&](const std::string& u) -> const ft::Finding* {
        for (const auto& f : fs)
            if (f.label.rfind(u, 0) == 0) return &f;
        return nullptr;
    };
    const ft::Finding* admin = by_user("admin");
    CHECK(admin && admin->type == "password-hash" &&
          admin->description.find("Weak") != std::string::npos);
    const ft::Finding* rootf = by_user("root");
    CHECK(rootf && rootf->description.find("sha512crypt") != std::string::npos &&
          rootf->description.find("Weak") == std::string::npos);
    const ft::Finding* legacy = by_user("legacy");
    CHECK(legacy && legacy->description.find("descrypt") != std::string::npos);
    const ft::Finding* guest = by_user("guest");
    CHECK(guest && guest->type == "empty-password");
    // Every hash finding is validated (structurally certain).
    for (const auto& f : fs)
        CHECK(f.confidence == static_cast<uint8_t>(ft::Confidence::Validated));
}

static void test_credstore_htpasswd() {
    std::string ht =
        "admin:$apr1$abc$0123456789abcdefghijkl\n"          // apr1, weak
        "user:$2y$05$abcdefghijklmnopqrstuvwxyzABCDE12\n";  // bcrypt, ok
    auto fs = cred("app/.htpasswd", ht);
    CHECK(fs.size() == 2);
    for (const auto& f : fs) CHECK(f.type == "htpasswd-hash");
}

static void test_credstore_dispatch() {
    CHECK(cred("etc/passwd", "root:x:0:0::/root:/bin/sh\n").empty());
    CHECK(cred("app/main.c", "int x;\n").empty());
}

// ---------------------------------------------------------------- binary version strings
static std::vector<ft::Component> binver(const std::string& content) {
    return ft::scan_binver(std::span<const uint8_t>(
                               reinterpret_cast<const uint8_t*>(content.data()), content.size()),
                           "bin/prog");
}

static void test_binver() {
    // "\x7f" "ELF" via explicit bytes (\x7f\x45\x4c\x46); banners separated by
    // spaces (is_elf only checks the first 4 bytes, the rest is arbitrary).
    std::string elf = std::string("\x7f\x45\x4c\x46", 4) +
                      " pad BusyBox v1.36.1 (2023-01-01) OpenSSL 1.1.1n Dropbear v2022.83 "
                      "more BusyBox v1.36.1 again end";
    auto cs = binver(elf);
    auto by = [&](const std::string& n) -> const ft::Component* {
        for (const auto& c : cs)
            if (c.name == n) return &c;
        return nullptr;
    };
    const ft::Component* bb = by("busybox");
    CHECK(bb && bb->version == "1.36.1");
    CHECK(bb && bb->source == "binary-version");
    CHECK(bb && bb->cpe == "cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*");
    CHECK(bb && bb->purl == "pkg:generic/busybox@1.36.1");
    const ft::Component* ossl = by("openssl");
    CHECK(ossl && ossl->version == "1.1.1n");
    const ft::Component* db = by("dropbear");
    CHECK(db && db->version == "2022.83");
    // busybox appears twice but is deduped to one component.
    size_t bb_count = 0;
    for (const auto& c : cs)
        if (c.name == "busybox") ++bb_count;
    CHECK(bb_count == 1);

    // Non-ELF content: version banners are ignored (noise in text/docs).
    std::string txt = "Release notes: built with BusyBox v1.36.1 and OpenSSL 1.1.1n.\n";
    CHECK(binver(txt).empty());

    // glibc + musl content banners.
    std::string glibc = std::string("\x7f\x45\x4c\x46", 4) +
                        " GNU C Library (GNU libc) stable release version 2.31. ";
    auto g = binver(glibc);
    CHECK(!g.empty() && g[0].name == "glibc" && g[0].version == "2.31");
    std::string musl = std::string("\x7f\x45\x4c\x46", 4) + " musl libc (arm)\nVersion 1.2.3\n";
    auto ms = binver(musl);
    CHECK(!ms.empty() && ms[0].name == "musl" && ms[0].version == "1.2.3");

    // TLS/crypto libs + openvpn + lua (single-value banners, with co-derived CPEs).
    std::string more = std::string("\x7f\x45\x4c\x46", 4) +
                       " mbed TLS 2.23.0 GnuTLS 3.6.8 OpenVPN 2.4.7 arm-linux Lua 5.1.5 done";
    auto cs2 = binver(more);
    auto by2 = [&](const std::string& n) -> const ft::Component* {
        for (const auto& c : cs2)
            if (c.name == n) return &c;
        return nullptr;
    };
    const ft::Component* mb = by2("mbedtls");
    CHECK(mb && mb->version == "2.23.0" &&
          mb->cpe == "cpe:2.3:a:arm:mbed_tls:2.23.0:*:*:*:*:*:*:*");
    const ft::Component* gt = by2("gnutls");
    CHECK(gt && gt->version == "3.6.8" && gt->cpe.find("gnu:gnutls") != std::string::npos);
    const ft::Component* ov = by2("openvpn");
    CHECK(ov && ov->version == "2.4.7" && ov->cpe.find("openvpn:openvpn") != std::string::npos);
    const ft::Component* lu = by2("lua");
    CHECK(lu && lu->version == "5.1.5" && lu->cpe.find("lua:lua") != std::string::npos);
    // LuaJIT must not match the Lua rule (different product).
    std::string ljit = std::string("\x7f\x45\x4c\x46", 4) + " LuaJIT 2.0.5 ";
    CHECK(binver(ljit).empty());
}

// ---------------------------------------------------------------- u-boot banner
static std::vector<ft::Component> uboot(const std::string& s) {
    return ft::scan_uboot_version(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()), s.size()), "ub");
}
static void test_uboot() {
    // NOT ELF-gated: u-boot images are raw. Capture just the YYYY.MM token.
    auto cs = uboot("\xd0\x0d\xfe\xed pad U-Boot 2019.04 (Apr 15 2019 - 10:00:00 +0000) more");
    CHECK(cs.size() == 1);
    if (!cs.empty()) {
        CHECK(cs[0].name == "u-boot" && cs[0].version == "2019.04");
        CHECK(cs[0].cpe == "cpe:2.3:a:denx:u-boot:2019.04:*:*:*:*:*:*:*");
        CHECK(cs[0].source == "bootloader-banner");
    }
    // A "-rc"/vendor suffix is dropped for a clean CPE version compare.
    auto rc = uboot("U-Boot 2023.04-rc2 (May 01 2023)");
    CHECK(rc.size() == 1 && rc[0].version == "2023.04");
    CHECK(uboot("random text, no bootloader here").empty());
    // u-boot is in the NVD product set so its CVEs get covered.
    bool has_uboot = false;
    for (auto& [v, p] : ft::binver_cpe_products())
        if (v == "denx" && p == "u-boot") has_uboot = true;
    CHECK(has_uboot);
}

// ---------------------------------------------------------------- kernel CVEs
static const ft::KernelCveResult* find_kcve(const std::vector<ft::KernelCveResult>& v,
                                            const std::string& cve) {
    for (const auto& k : v)
        if (k.cve == cve) return &k;
    return nullptr;
}

// ------------------------------------------------------------------ kallsyms
// Build a minimal but format-faithful kallsyms image: an absolute-address array
// (the anchor), num_syms, the token-compressed names blob, then the 256-entry
// token table + index. Tokens are single characters, so a symbol's token-index
// bytes are just its characters — keeps the fixture readable while exercising
// the real decoder (token-table location, address anchor, name decode).
static std::vector<uint8_t> build_kallsyms(const std::vector<std::string>& syms) {
    std::vector<uint8_t> b;
    auto u32 = [&](uint32_t v) {
        b.push_back(v & 0xff);
        b.push_back((v >> 8) & 0xff);
        b.push_back((v >> 16) & 0xff);
        b.push_back((v >> 24) & 0xff);
    };
    size_t n = syms.size();
    for (size_t i = 0; i < n; ++i) u32(0x80000000u + uint32_t(i * 4));  // addresses (monotonic)
    u32(uint32_t(n));                                                    // kallsyms_num_syms
    for (const auto& s : syms) {                                         // kallsyms_names
        b.push_back(uint8_t(s.size()));  // token count == char count (1 char/token)
        for (char c : s) b.push_back(uint8_t(c));
    }
    if (b.size() & 1) b.push_back(0x00);  // 2-align the token tables (as the linker does)
    // token_table: entry i = char i (i==0 -> '.', unused) then NUL, at offset 2i.
    for (int i = 0; i < 256; ++i) {
        b.push_back(i == 0 ? uint8_t('.') : uint8_t(i));
        b.push_back(0x00);
    }
    for (int i = 0; i < 256; ++i) {  // token_index: 2*i, little-endian
        uint16_t off = uint16_t(2 * i);
        b.push_back(off & 0xff);
        b.push_back((off >> 8) & 0xff);
    }
    return b;
}

static void test_kallsyms() {
    std::vector<std::string> syms = {"Tcommit_creds", "Tprepare_kernel_cred", "Tpacket_rcv",
                                     "Tovl_fill_super"};
    while (syms.size() < 2100) syms.push_back("Tsym" + std::to_string(syms.size()));  // >= anchor min
    auto blob = build_kallsyms(syms);
    auto ks = ft::decode_kallsyms(std::span<const uint8_t>(blob.data(), blob.size()));
    CHECK(ks.has_value());
    if (ks) {
        CHECK(ks->complete);
        CHECK(ks->has("commit_creds"));         // type char stripped
        CHECK(ks->has("packet_rcv"));
        CHECK(ks->has("ovl_fill_super"));
        CHECK(!ks->has("nft_do_chain"));        // not in the fixture
        CHECK(ks->names.size() == syms.size());
    }
    // Garbage / too small -> no table, no crash.
    std::vector<uint8_t> junk(8192, 0x41);
    CHECK(!ft::decode_kallsyms(std::span<const uint8_t>(junk.data(), junk.size())).has_value());
}

static void test_kconfig_infer() {
    using namespace ft;
    std::string ev;

    // Source 1: a real .config is authoritative.
    {
        KernelConfigView v;
        std::string cfg =
            "#\n# Automatically generated file\n#\n"
            "CONFIG_PACKET=y\nCONFIG_NF_TABLES=m\n# CONFIG_IO_URING is not set\n";
        infer_from_kconfig_text(cfg, v);
        CHECK(v.authoritative);
        CHECK(config_option_state(v, "CONFIG_PACKET", ev) == KcveState::Applicable);
        CHECK(config_option_state(v, "CONFIG_NF_TABLES", ev) == KcveState::Applicable);  // =m counts
        // Authoritative: anything not enabled is ruled out (even without a symbol).
        CHECK(config_option_state(v, "CONFIG_IO_URING", ev) == KcveState::RuledOut);
        CHECK(config_option_state(v, "CONFIG_TIPC", ev) == KcveState::RuledOut);
    }

    // Source 2: modules (a .ko path and a modules.builtin manifest).
    {
        KernelConfigView v;
        infer_from_ko_path("lib/modules/5.4.0/kernel/net/mac80211/mac80211.ko", v);
        std::string mb = "kernel/net/netfilter/nf_tables.ko\nkernel/fs/overlayfs/overlay.ko\n";
        infer_from_modules_builtin(std::span<const uint8_t>(
                                       reinterpret_cast<const uint8_t*>(mb.data()), mb.size()),
                                   v);
        CHECK(v.modules_seen);
        CHECK(config_option_state(v, "CONFIG_MAC80211", ev) == KcveState::Applicable);
        CHECK(ev == "ko-file");
        CHECK(config_option_state(v, "CONFIG_NF_TABLES", ev) == KcveState::Applicable);
        CHECK(config_option_state(v, "CONFIG_OVERLAY_FS", ev) == KcveState::Applicable);
        // A .ko outside a modules tree must not count.
        KernelConfigView v2;
        infer_from_ko_path("usr/lib/foo/mac80211.ko", v2);
        CHECK(config_option_state(v2, "CONFIG_MAC80211", ev) == KcveState::Unknown);
    }

    // Source 3: kallsyms rule-in and (builtin-only) rule-out; modular stays unknown.
    {
        KernelConfigView v;
        Kallsyms ks;
        ks.complete = true;
        ks.names.insert("packet_rcv");
        ks.names.insert("ovl_fill_super");
        // no io_uring / user_ns / nft symbols
        infer_from_kallsyms(ks, v);
        CHECK(config_option_state(v, "CONFIG_PACKET", ev) == KcveState::Applicable);
        CHECK(ev == "kallsyms");
        // builtin-only subsystem, absent on a complete table -> ruled out
        CHECK(config_option_state(v, "CONFIG_IO_URING", ev) == KcveState::RuledOut);
        CHECK(config_option_state(v, "CONFIG_USER_NS", ev) == KcveState::RuledOut);
        // modular-capable subsystem, absent but no module info -> undetermined
        CHECK(config_option_state(v, "CONFIG_NF_TABLES", ev) == KcveState::Unknown);
        CHECK(config_option_state(v, "CONFIG_MAC80211", ev) == KcveState::Unknown);
    }

    // Source 3+2: complete kallsyms + a modules tree lets modular options rule out.
    {
        KernelConfigView v;
        Kallsyms ks;
        ks.complete = true;
        ks.names.insert("commit_creds");
        infer_from_kallsyms(ks, v);
        v.modules_seen = true;  // a /lib/modules tree was present, nf_tables.ko not in it
        CHECK(config_option_state(v, "CONFIG_NF_TABLES", ev) == KcveState::RuledOut);
        CHECK(ev == "kallsyms+modules");
    }

    // merge_view keeps the highest-trust evidence label.
    {
        KernelConfigView a, bkv;
        Kallsyms ks;
        ks.names.insert("packet_rcv");
        infer_from_kallsyms(ks, a);  // PACKET via kallsyms
        std::string mb = "kernel/net/packet/af_packet.ko\n";
        infer_from_modules_builtin(std::span<const uint8_t>(
                                       reinterpret_cast<const uint8_t*>(mb.data()), mb.size()),
                                   bkv);  // PACKET via modules.builtin (higher trust)
        merge_view(a, bkv);
        CHECK(config_option_state(a, "CONFIG_PACKET", ev) == KcveState::Applicable);
        CHECK(ev == "modules.builtin");
    }

    // looks_like_kconfig: a real config yes, a stray fragment no.
    {
        std::string real = "#\n# Automatically generated file\n# Linux Kernel Configuration\n";
        for (int i = 0; i < 60; ++i) real += "CONFIG_FOO" + std::to_string(i) + "=y\n";
        for (int i = 0; i < 20; ++i) real += "# CONFIG_BAR" + std::to_string(i) + " is not set\n";
        CHECK(looks_like_kconfig(
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(real.data()), real.size())));
        std::string frag = "see CONFIG_FOO and CONFIG_BAR in the manual\nCONFIG_X=1\n";
        CHECK(!looks_like_kconfig(
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(frag.data()), frag.size())));
        // A buildroot/OpenWrt .config is just as CONFIG_-dense but is NOT a kernel
        // config: no kernel markers -> must be rejected (else it would falsely
        // rule every kernel subsystem out).
        std::string ow = "#\n# Automatically generated file\n# OpenWrt Configuration\n";
        for (int i = 0; i < 60; ++i) ow += "CONFIG_PACKAGE_util" + std::to_string(i) + "=y\n";
        for (int i = 0; i < 20; ++i) ow += "# CONFIG_TARGET_x" + std::to_string(i) + " is not set\n";
        CHECK(!looks_like_kconfig(
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(ow.data()), ow.size())));
    }
}
static const ft::KernelConfigView* NOCFG = nullptr;
static void test_kernelcve() {
    // No config: in-range CVEs undetermined, flagged "config unknown".
    auto r = ft::kernel_cve_scan("5.16.5", NOCFG);
    const auto* dp = find_kcve(r, "CVE-2022-0847");  // Dirty Pipe 5.8..5.16.11
    CHECK(dp && dp->state == ft::KcveState::Unknown && !dp->applicable &&
          dp->reason.find("config unknown") != std::string::npos);
    CHECK(find_kcve(r, "CVE-2016-5195") == nullptr);  // Dirty COW fixed 4.8.3 -> out of range

    // Config gating: NF_TABLES present -> nftables applies; io_uring absent -> ruled out.
    std::set<std::string> cfg = {"CONFIG_NF_TABLES"};
    auto r2 = ft::kernel_cve_scan("6.3", &cfg);
    const auto* nft = find_kcve(r2, "CVE-2023-32233");
    CHECK(nft && nft->applicable);
    const auto* iou = find_kcve(r2, "CVE-2023-2598");  // needs CONFIG_IO_URING
    CHECK(iou && !iou->applicable && iou->reason.find("CONFIG_IO_URING") != std::string::npos);

    // Mitigation: unpriv-bpf-off rules out the eBPF LPE.
    std::set<std::string> cfg2 = {"CONFIG_BPF_SYSCALL", "CONFIG_BPF_UNPRIV_DEFAULT_OFF"};
    auto r3 = ft::kernel_cve_scan("5.10", &cfg2);
    const auto* ebpf = find_kcve(r3, "CVE-2021-3490");  // 5.7..5.13
    CHECK(ebpf && !ebpf->applicable && ebpf->reason.find("mitigated") != std::string::npos);

    // A kernel newer than every curated fix -> nothing in range.
    CHECK(find_kcve(ft::kernel_cve_scan("6.10", NOCFG), "CVE-2022-0847") == nullptr);
    // Empty version -> nothing.
    CHECK(ft::kernel_cve_scan("", NOCFG).empty());

    // TowelRoot (futex, no gate): applies to an old kernel, ruled out by version later.
    CHECK(find_kcve(ft::kernel_cve_scan("3.4.0", NOCFG), "CVE-2014-3153") != nullptr);
    CHECK(find_kcve(ft::kernel_cve_scan("4.4.0", NOCFG), "CVE-2014-3153") == nullptr);  // fixed 3.15

    // Remote WiFi RCE gated on CONFIG_MAC80211 (introduced 5.1, fixed 6.1).
    std::set<std::string> wifi = {"CONFIG_MAC80211"};
    auto rw = ft::kernel_cve_scan("5.10", &wifi);
    const auto* mb = find_kcve(rw, "CVE-2022-42719");
    CHECK(mb && mb->applicable && mb->impact == std::string("RCE"));
    auto rw2 = ft::kernel_cve_scan("5.10", NOCFG);  // no config -> unknown, still listed
    const auto* mb2 = find_kcve(rw2, "CVE-2022-42719");
    CHECK(mb2 && mb2->state == ft::KcveState::Unknown &&
          mb2->reason.find("config unknown") != std::string::npos);
    // Without MAC80211 the WiFi bug is ruled out. (Bind the vector to a local:
    // find_kcve returns a pointer into it, so it must outlive the deref.)
    std::set<std::string> nowifi = {"CONFIG_NF_TABLES"};
    auto rw3 = ft::kernel_cve_scan("5.10", &nowifi);
    const auto* mb3 = find_kcve(rw3, "CVE-2022-42719");
    CHECK(mb3 && !mb3->applicable && mb3->reason.find("CONFIG_MAC80211") != std::string::npos);
    // Below the introduced version (5.1) the WiFi bug is out of range entirely.
    auto rw4 = ft::kernel_cve_scan("4.9", &wifi);
    CHECK(find_kcve(rw4, "CVE-2022-42719") == nullptr);

    // Android Binder gated on CONFIG_ANDROID_BINDER_IPC.
    std::set<std::string> binder = {"CONFIG_ANDROID_BINDER_IPC"};
    auto rb = ft::kernel_cve_scan("4.14", &binder);
    const auto* bd = find_kcve(rb, "CVE-2019-2215");
    CHECK(bd && bd->applicable);

    // Tri-state view: inferred (non-authoritative) config yields Applicable /
    // RuledOut / Unknown as the evidence supports.
    ft::KernelConfigView v;
    v.enabled.insert("CONFIG_PACKET");        // proven present (e.g. kallsyms)
    v.evidence["CONFIG_PACKET"] = "kallsyms";
    v.kallsyms_complete = true;
    v.not_builtin.insert("CONFIG_IO_URING");  // builtin-only, absent -> ruled out
    v.not_builtin.insert("CONFIG_NF_TABLES"); // modular, absent, no modules -> unknown
    auto tv = ft::kernel_cve_scan("5.10", &v);
    const auto* pk = find_kcve(tv, "CVE-2021-22600");  // af_packet, needs CONFIG_PACKET (fixed 5.16)
    CHECK(pk && pk->state == ft::KcveState::Applicable);
    const auto* io = find_kcve(tv, "CVE-2022-2602");  // needs CONFIG_IO_URING
    CHECK(io && io->state == ft::KcveState::RuledOut && io->reason.find("kallsyms") != std::string::npos);
    const auto* nf = find_kcve(tv, "CVE-2023-32233");  // needs CONFIG_NF_TABLES
    CHECK(nf && nf->state == ft::KcveState::Unknown);
}

// ---------------------------------------------------------------- inflate
static void test_inflate() {
    // gzip.compress(b"hello inflate world hello inflate world\n")
    static const uint8_t gz[] = {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x57, 0xc8, 0xcc, 0x4b, 0xcb, 0x49, 0x2c, 0x49, 0x55, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x51,
        0xc8, 0xc0, 0x14, 0xe3, 0x02, 0x00, 0x47, 0x54, 0x05, 0xec, 0x28, 0x00, 0x00, 0x00};
    auto out = ft::gzip_inflate(std::span<const uint8_t>(gz, sizeof(gz)));
    CHECK(out.has_value());
    if (out) {
        std::string s(out->begin(), out->end());
        CHECK(s == "hello inflate world hello inflate world\n");
    }
    // garbage / truncation never crashes or hangs.
    CHECK(!ft::gzip_inflate(std::span<const uint8_t>(gz, 5)).has_value());
    std::string junk(64, '\xff');
    CHECK(!ft::gzip_inflate(std::span<const uint8_t>(
              reinterpret_cast<const uint8_t*>(junk.data()), junk.size())).has_value());
}

// ---------------------------------------------------------------- kernel banner
static std::vector<ft::Component> kern(const std::string& s) {
    return ft::scan_kernel_version(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()), s.size()), "k");
}
static void test_kernel() {
    auto cs = kern("garbage Linux version 4.4.94 (builder@host) (gcc 7.3) #1 SMP Mon");
    CHECK(cs.size() == 1);
    if (!cs.empty()) {
        CHECK(cs[0].name == "linux_kernel" && cs[0].version == "4.4.94");
        CHECK(cs[0].cpe == "cpe:2.3:o:linux:linux_kernel:4.4.94:*:*:*:*:*:*:*");
        CHECK(cs[0].source == "kernel-banner");
    }
    CHECK(kern("Linux version 2.6.36 blah").size() == 1);       // old two-part-ish
    CHECK(kern("the linux operating system, version 5").empty());  // no false positive
}

// ---------------------------------------------------------------- filename versions
static void test_filever() {
    auto uc = ft::scan_filename_version("lib/libuClibc-0.9.30.so");
    CHECK(uc.size() == 1 && uc[0].name == "uclibc" && uc[0].version == "0.9.30");
    CHECK(uc.size() == 1 && uc[0].source == "filename" &&
          uc[0].cpe == "cpe:2.3:a:uclibc:uclibc:0.9.30:*:*:*:*:*:*:*");
    auto uc2 = ft::scan_filename_version("lib/ld-uClibc-1.0.31.so");
    CHECK(uc2.size() == 1 && uc2[0].version == "1.0.31");
    auto gl = ft::scan_filename_version("lib/libc-2.31.so");
    CHECK(gl.size() == 1 && gl[0].name == "glibc" && gl[0].version == "2.31" &&
          gl[0].cpe.find("gnu:glibc") != std::string::npos);
    auto gl2 = ft::scan_filename_version("lib/ld-2.25.so");
    CHECK(gl2.size() == 1 && gl2[0].name == "glibc" && gl2[0].version == "2.25");
    // not libc: no match, no false positive
    CHECK(ft::scan_filename_version("lib/libcurl.so.4.5.0").empty());
    CHECK(ft::scan_filename_version("bin/busybox").empty());
    CHECK(ft::scan_filename_version("lib/libcrypto.so.1.1").empty());
}

static void test_sbom_emit() {
    std::vector<ft::Component> cs;
    ft::Component c;
    c.name = "busybox"; c.version = "1.30.1"; c.purl = "pkg:deb/busybox@1.30.1?arch=armhf";
    c.license = "GPL-2.0-only"; c.source = "dpkg"; c.confidence = 95;
    cs.push_back(c);
    auto cdx = ft::json_parse(ft::emit_cyclonedx(cs, "0.1.0"));
    CHECK(cdx && cdx->get_str("bomFormat") == "CycloneDX" && cdx->get_str("specVersion") == "1.5");
    if (cdx) {
        const ft::JsonValue* comps = cdx->find("components");
        CHECK(comps && comps->arr.size() == 1 && comps->arr[0].get_str("name") == "busybox");
    }
    auto spdx = ft::json_parse(ft::emit_spdx(cs, "0.1.0"));
    CHECK(spdx && spdx->get_str("spdxVersion") == "SPDX-2.3");
}

// ---------------------------------------------------------------- user rules
static void test_userrules() {
    // Custom delimiter: the regex contains )" which would end a plain R"(...)".
    std::string doc = R"JSON({
      "path_rules": [
        {"glob":"**/*.p12","category":"crypto","type":"pkcs12","description":"keystore"}
      ],
      "content_rules": [
        {"type":"vendor-cred","category":"secret","anchors":["ADMIN_PW"],
         "regex":"ADMIN_PW\\s*=\\s*(\\S+)","description":"vendor pw"},
        {"type":"internal-host","category":"config","anchors":["update.corp.local"]}
      ]
    })JSON";
    ft::UserRules ur = ft::parse_user_rules(doc);
    CHECK(ur.ok());
    CHECK(ur.paths.size() == 1 && ur.paths[0].type == "pkcs12");
    CHECK(ur.content.size() == 2);

    // Drive the user content rules through an engine and confirm extraction.
    ft::Engine e(ur.content, ur.paths);
    std::string data = "ADMIN_PW = SuperSecret_9xQ7\nota = update.corp.local\n";
    ft::Reader r(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(data.data()),
                                          data.size()));
    auto fs = e.scan_content(r);
    const ft::Finding* cred = find_type(fs, "vendor-cred");
    CHECK(cred && cred->label == "SuperSecret_9xQ7");  // regex capture group 1
    const ft::Finding* host = find_type(fs, "internal-host");
    CHECK(host && host->label == "update.corp.local");  // keyword presence
    // Path rule works through the same engine.
    CHECK(e.scan_paths("etc/store.p12", 0).size() == 1);

    // Errors: bad JSON, missing anchors, bad regex.
    CHECK(!ft::parse_user_rules("not json").ok());
    CHECK(!ft::parse_user_rules(R"({"content_rules":[{"type":"x"}]})").ok());
    CHECK(!ft::parse_user_rules(
               R"JSON({"content_rules":[{"anchors":["x"],"regex":"("}]})JSON").ok());
}

// ---------------------------------------------------------------- version compare
static void test_version() {
    auto s = [](const char* a, const char* b) {
        int g = ft::deb_vercmp(a, b);
        return g < 0 ? -1 : (g > 0 ? 1 : 0);
    };
    CHECK(s("1.0", "1.0") == 0);
    CHECK(s("1.0", "2.0") == -1);
    CHECK(s("1.0~rc1", "1.0") == -1);       // tilde sorts before
    CHECK(s("1.0", "1.0-1") == -1);         // revision present > absent
    CHECK(s("1:1.0", "2.0") == 1);          // epoch dominates
    CHECK(s("1.1.1n", "1.1.1w") == -1);     // openssl letter suffix
    CHECK(s("1.36.1-r5", "1.36.1-r10") == -1);
    CHECK(s("1.10", "1.9") == 1);           // numeric, not lexical
}

// ---------------------------------------------------------------- cve join
static void test_cve() {
    // affected-range evaluation (consistent epoch: fixed at 1.30.1-6, no epoch)
    std::vector<ft::OsvEvent> ev = {{'i', "0"}, {'f', "1.30.1-6"}};
    CHECK(ft::osv_is_affected("1.30.1-5", ev));   // before the fix
    CHECK(!ft::osv_is_affected("1.30.1-6", ev));  // exactly the fix -> not affected
    CHECK(!ft::osv_is_affected("2.0", ev));       // after the fix (same epoch)
    // Epoch matters: an epoch-1 fix outranks a bare 2.0, so 2.0 is still "before".
    CHECK(ft::osv_is_affected("2.0", {{'i', "0"}, {'f', "1:1.30.1-6"}}));
    std::vector<ft::OsvEvent> ev2 = {{'i', "0"}, {'l', "1.5"}};  // last_affected
    CHECK(ft::osv_is_affected("1.5", ev2));
    CHECK(!ft::osv_is_affected("1.6", ev2));

    // join
    ft::OsvDb db;
    db.index[ft::OsvDb::key("Debian", "busybox")].push_back(
        {"CVE-2021-28831", {{'i', "0"}, {'f', "1:1.30.1-6"}}, "CVSS:3.1/AV:N", "busybox bug", ""});
    db.index[ft::OsvDb::key("Alpine", "openssl")].push_back(
        {"CVE-2022-0778", {{'i', "0"}, {'f', "1.1.1n-r0"}}, "", "infinite loop", ""});

    auto mk = [](std::string name, std::string ver, std::string src) {
        ft::Component c;
        c.name = name;
        c.version = ver;
        c.source = src;
        c.purl = "pkg:x/" + name + "@" + ver;
        return c;
    };
    std::vector<ft::Component> comps = {
        mk("busybox", "1.30.1-5", "dpkg"),     // vulnerable
        mk("openssl", "1.1.1m-r0", "apk"),     // vulnerable (< 1.1.1n-r0)
        mk("openssl", "3.6.4", "binary-version"),  // no OSV ecosystem -> skipped
        mk("curl", "8.0.0", "dpkg"),           // package not in db -> no match
    };
    auto matches = ft::cve_join(db, comps);
    CHECK(matches.size() == 2);
    bool bb = false, ossl = false;
    for (const auto& m : matches) {
        if (m.cve_id == "CVE-2021-28831" && m.component == "busybox@1.30.1-5") bb = true;
        if (m.cve_id == "CVE-2022-0778" && m.component == "openssl@1.1.1m-r0") ossl = true;
    }
    CHECK(bb && ossl);

    // A patched component yields no CVE.
    auto none = ft::cve_join(db, {mk("busybox", "1:1.30.1-6", "dpkg")});
    CHECK(none.empty());

    // Release precision: two release-tagged entries; a known release picks one.
    ft::OsvDb rdb;
    rdb.index[ft::OsvDb::key("Debian", "curl")].push_back(
        {"CVE-A", {{'i', "0"}, {'f', "7.0-1"}}, "", "", "11"});   // fixed in Debian 11
    rdb.index[ft::OsvDb::key("Debian", "curl")].push_back(
        {"CVE-B", {{'i', "0"}, {'f', "9.0-1"}}, "", "", "12"});   // fixed in Debian 12
    auto old = mk("curl", "6.0-1", "dpkg");  // affected by both ranges version-wise
    // release-agnostic -> both match
    CHECK(ft::cve_join(rdb, {old}).size() == 2);
    // release 11 -> only the Debian:11 entry
    auto r11 = ft::cve_join(rdb, {old}, "debian", "11");
    CHECK(r11.size() == 1 && r11[0].cve_id == "CVE-A");
    CHECK(r11.size() == 1 && r11[0].basis.find("Debian:11") != std::string::npos);

    // rpm ecosystem is chosen from the image's distro id.
    ft::OsvDb rh;
    rh.index[ft::OsvDb::key("Red Hat", "openssl")].push_back(
        {"CVE-RH", {{'i', "0"}, {'f', "3.0.0"}}, "", "", ""});
    ft::Component rc = mk("openssl", "1.1.1", "rpm");
    CHECK(ft::cve_join(rh, {rc}, "rocky").empty());          // rocky -> Rocky Linux, no match
    CHECK(ft::cve_join(rh, {rc}, "rhel").size() == 1);       // rhel -> Red Hat, matches

    // dpkg -> Ubuntu when os-release id is ubuntu, else Debian. Ubuntu version
    // strings (1.1.1f-1ubuntuN.M) compare via the same dpkg algorithm.
    CHECK(ft::osv_is_affected("1.1.1f-1ubuntu2.10", {{'i', "0"}, {'f', "1.1.1f-1ubuntu2.12"}}));
    CHECK(!ft::osv_is_affected("1.1.1f-1ubuntu2.12", {{'i', "0"}, {'f', "1.1.1f-1ubuntu2.12"}}));
    ft::OsvDb ub;
    ub.index[ft::OsvDb::key("Ubuntu", "openssl")].push_back(
        {"CVE-U", {{'i', "0"}, {'f', "1.1.1f-1ubuntu2.12"}}, "", "", "20.04"});
    ft::Component uc = mk("openssl", "1.1.1f-1ubuntu2.10", "dpkg");  // vulnerable on Ubuntu
    CHECK(ft::cve_join(ub, {uc}, "ubuntu", "20.04").size() == 1);    // ubuntu id -> Ubuntu eco
    auto ur = ft::cve_join(ub, {uc}, "ubuntu", "20.04");
    CHECK(!ur.empty() && ur[0].basis.find("Ubuntu:20.04") != std::string::npos);
    CHECK(ft::cve_join(ub, {uc}, "debian", "11").empty());          // debian id -> Debian eco, no Ubuntu data
    CHECK(ft::cve_join(ub, {uc}, "ubuntu", "18.04").empty());       // release precision: 18.04 != 20.04

    // reconcile: same (cve, component) from two sources -> one row, richer CVSS.
    std::vector<ft::CveMatch> dup = {
        {"CVE-X", "curl@8.0", "", "", "osv", ""},
        {"CVE-X", "curl@8.0", "", "CVSS:3.1/AV:N", "nvd-cpe-range", ""}};
    auto rec = ft::reconcile_cves(dup);
    CHECK(rec.size() == 1);
    CHECK(rec.size() == 1 && rec[0].severity == "CVSS:3.1/AV:N");
    CHECK(rec.size() == 1 && rec[0].basis.find("osv") != std::string::npos &&
          rec[0].basis.find("nvd-cpe-range") != std::string::npos);

    // The compact binary index round-trips: write_osv_index -> OsvIndex::open ->
    // lookup + join (the production path). Two keys, both with a summary.
    const char* idx = "/tmp/mithril_ut_osv.mdb";
    std::vector<ft::OsvIndexEntry> ents = {
        {"Debian", "busybox", "CVE-2021-28831", "CVSS:3.1", "", "bug", {{'i', "0"}, {'f', "1:1.30.1-6"}}},
        {"Alpine", "openssl", "CVE-2022-0778", "", "", "loop", {{'i', "0"}, {'f', "1.1.1n-r0"}}},
    };
    std::string werr;
    CHECK(ft::write_osv_index(idx, ents, 12345, "test-source", werr));
    ft::OsvIndex oi;
    CHECK(oi.open(idx));
    CHECK(oi.vuln_count() == 2 && oi.generated() == 12345 && oi.source() == "test-source");
    auto m = ft::cve_join(oi, {mk("busybox", "1.30.1-5", "dpkg")});
    CHECK(m.size() == 1 && m[0].cve_id == "CVE-2021-28831");
    CHECK(m.size() == 1 && m[0].severity == "CVSS:3.1" && m[0].summary == "bug");
    CHECK(oi.lookup("Debian", "no-such-pkg").empty());              // missing key
    CHECK(ft::cve_join(oi, {mk("busybox", "1:1.30.1-6", "dpkg")}).empty());  // patched
    // a second key resolves independently (binary search over the key dir)
    auto m2 = ft::cve_join(oi, {mk("openssl", "1.1.1m-r0", "apk")});
    CHECK(m2.size() == 1 && m2[0].cve_id == "CVE-2022-0778");
    std::remove(idx);
}

// ---------------------------------------------------------------- nvd/cpe join
static void test_nvd() {
    // affected-range evaluation
    ft::NvdVuln exact;
    exact.version = "1.1.1";
    CHECK(ft::nvd_is_affected("1.1.1", exact));
    CHECK(!ft::nvd_is_affected("1.1.2", exact));

    ft::NvdVuln rng;
    rng.start_incl = "1.0.0";
    rng.end_excl = "1.1.1n";
    CHECK(ft::nvd_is_affected("1.0.5", rng));
    CHECK(ft::nvd_is_affected("1.1.1m", rng));
    CHECK(!ft::nvd_is_affected("1.1.1n", rng));   // end excluded
    CHECK(!ft::nvd_is_affected("0.9.8", rng));    // before start

    ft::NvdVuln allv;  // no bounds, no exact -> every version
    CHECK(ft::nvd_is_affected("9.9.9", allv));

    // join against CPE-bearing (binary-version) components
    ft::NvdDb db;
    ft::NvdVuln v;
    v.id = "CVE-2022-0778";
    v.cvss = "CVSS:3.1/AV:N";
    v.end_excl = "1.1.1n";
    db.index[ft::NvdDb::key("openssl", "openssl")].push_back(v);

    auto mk = [](std::string name, std::string ver, std::string cpe) {
        ft::Component c;
        c.name = name;
        c.version = ver;
        c.source = "binary-version";
        c.cpe = cpe;
        c.purl = "pkg:generic/" + name + "@" + ver;
        return c;
    };
    std::vector<ft::Component> comps = {
        mk("openssl", "1.1.1m", "cpe:2.3:a:openssl:openssl:1.1.1m:*:*:*:*:*:*:*"),  // vulnerable
        mk("openssl", "3.6.4", "cpe:2.3:a:openssl:openssl:3.6.4:*:*:*:*:*:*:*"),    // patched
    };
    // A dpkg component (no CPE) must be ignored by the NVD join.
    ft::Component dpkg;
    dpkg.name = "openssl";
    dpkg.version = "1.1.1m";
    dpkg.source = "dpkg";
    comps.push_back(dpkg);

    auto m = ft::nvd_join(db, comps);
    CHECK(m.size() == 1);
    CHECK(m.size() == 1 && m[0].cve_id == "CVE-2022-0778" && m[0].component == "openssl@1.1.1m");
    CHECK(m.size() == 1 && m[0].basis.find("nvd-cpe") != std::string::npos);
}

// ---------------------------------------------------------------- rpm
static void test_rpm() {
    std::vector<uint8_t> h;
    auto be32 = [&](uint32_t x) {
        h.push_back(x >> 24); h.push_back(x >> 16); h.push_back(x >> 8); h.push_back(x);
    };
    for (uint8_t b : {0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}) h.push_back(b);  // magic + reserved
    be32(4);   // nindex
    be32(28);  // hsize
    auto ie = [&](uint32_t tag, uint32_t off) { be32(tag); be32(6); be32(off); be32(1); };
    ie(1000, 0); ie(1001, 8); ie(1002, 15); ie(1022, 21);  // NAME/VERSION/RELEASE/ARCH
    auto add = [&](const char* s) { for (const char* p = s; *p; ++p) h.push_back(*p); h.push_back(0); };
    add("busybox"); add("1.30.1"); add("1.el8"); add("x86_64");  // data store (28 bytes)

    auto cs = ft::scan_rpm("var/lib/rpm/Packages",
                           std::span<const uint8_t>(h.data(), h.size()));
    CHECK(cs.size() == 1);
    if (!cs.empty()) {
        CHECK(cs[0].name == "busybox");
        CHECK(cs[0].version == "1.30.1-1.el8");
        CHECK(cs[0].source == "rpm");
        CHECK(cs[0].purl == "pkg:rpm/busybox@1.30.1-1.el8?arch=x86_64");
    }
    // dispatch: a non-rpm path yields nothing even with the same bytes
    CHECK(ft::scan_rpm("etc/passwd", std::span<const uint8_t>(h.data(), h.size())).empty());
    // garbage never crashes / yields nothing
    std::string junk(200, '\xff');
    CHECK(ft::parse_rpm_db(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(junk.data()),
                                                    junk.size()), "x").empty());
}

// ---------------------------------------------------------------- language manifests
static std::vector<ft::Component> lm(const std::string& relpath, const std::string& content) {
    return ft::scan_langmanifest(relpath, std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(content.data()), content.size()));
}

static void test_langmanifest() {
    // npm package-lock v3
    auto npm = lm("app/package-lock.json",
                  R"({"lockfileVersion":3,"packages":{"":{"name":"root"},)"
                  R"("node_modules/lodash":{"version":"4.17.19"},)"
                  R"("node_modules/@scope/pkg":{"version":"1.0.0"}}})");
    const ft::Component* lodash = find_comp(npm, "lodash");
    CHECK(lodash && lodash->version == "4.17.19" && lodash->source == "npm");
    CHECK(lodash && lodash->purl == "pkg:npm/lodash@4.17.19");

    // requirements.txt (only exact == pins)
    auto py = lm("requirements.txt", "flask==1.1.1\nrequests>=2.0\n# comment\nurllib3==1.25.8 ; x\n");
    CHECK(py.size() == 2);
    CHECK(find_comp(py, "flask") && find_comp(py, "flask")->purl == "pkg:pypi/flask@1.1.1");
    CHECK(find_comp(py, "urllib3") && find_comp(py, "urllib3")->version == "1.25.8");
    CHECK(find_comp(py, "requests") == nullptr);  // range, not pinned

    // go.mod
    auto go = lm("go.mod", "module example.com/x\n\ngo 1.20\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n"
                           "\tgolang.org/x/net v0.7.0 // indirect\n)\n");
    CHECK(find_comp(go, "github.com/pkg/errors") &&
          find_comp(go, "github.com/pkg/errors")->version == "v0.9.1");
    CHECK(find_comp(go, "golang.org/x/net") &&
          find_comp(go, "golang.org/x/net")->version == "v0.7.0");  // trailing // indirect stripped

    // Cargo.lock
    auto rust = lm("Cargo.lock", "[[package]]\nname = \"serde\"\nversion = \"1.0.130\"\n\n"
                                 "[[package]]\nname = \"libc\"\nversion = \"0.2.100\"\n");
    CHECK(find_comp(rust, "serde") && find_comp(rust, "serde")->purl == "pkg:cargo/serde@1.0.130");
    CHECK(rust.size() == 2);

    // Gemfile.lock
    auto gem = lm("Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n"
                                  "    rack (2.2.3)\n    rails (6.0.3)\n\nPLATFORMS\n  ruby\n");
    CHECK(find_comp(gem, "rack") && find_comp(gem, "rack")->version == "2.2.3");
    CHECK(gem.size() == 2);

    // a non-manifest file -> nothing
    CHECK(lm("src/main.c", "int x;\n").empty());
}

// ---------------------------------------------------------------- licenses
static std::vector<std::string> lic_text(const std::string& s) {
    return ft::identify_license_text(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(s.data()), s.size()));
}
static std::vector<ft::Finding> lic_scan(const std::string& path, const std::string& s) {
    return ft::scan_licenses(path, std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(s.data()), s.size()));
}

static void test_license() {
    // license-file text identification
    auto gpl = lic_text("GNU GENERAL PUBLIC LICENSE\n Version 2, June 1991\n ...");
    CHECK(gpl.size() == 1 && gpl[0] == "GPL-2.0");
    auto gpl3 = lic_text("GNU GENERAL PUBLIC LICENSE\n Version 3, 29 June 2007\n");
    CHECK(gpl3.size() == 1 && gpl3[0] == "GPL-3.0");
    auto lgpl3 = lic_text("GNU LESSER GENERAL PUBLIC LICENSE\n Version 3, 29 June 2007\n");
    CHECK(lgpl3.size() == 1 && lgpl3[0] == "LGPL-3.0");
    CHECK(lic_text("Permission is hereby granted, free of charge, to any person") ==
          std::vector<std::string>{"MIT"});
    CHECK(lic_text("Apache License\n Version 2.0, January 2004") ==
          std::vector<std::string>{"Apache-2.0"});
    auto bsd = lic_text("Redistribution and use in source and binary forms ... Neither the name of");
    CHECK(bsd.size() == 1 && bsd[0] == "BSD-3-Clause");
    auto bsd4 = lic_text("Redistribution and use in source and binary forms ... All advertising "
                         "materials mentioning features ... Neither the name of");
    CHECK(bsd4.size() == 1 && bsd4[0] == "BSD-4-Clause");  // advertising clause wins
    CHECK(lic_text("This is free and unencumbered software released into the public domain") ==
          std::vector<std::string>{"Unlicense"});
    CHECK(lic_text("Eclipse Public License - v 2.0") == std::vector<std::string>{"EPL-2.0"});

    // LGPL-2.0 ("Library General Public License", v2 1991) must NOT be GPL-2.0.
    auto lgpl2 = lic_text("GNU LIBRARY GENERAL PUBLIC LICENSE\n Version 2, June 1991\n");
    CHECK(lgpl2.size() == 1 && lgpl2[0] == "LGPL-2.0");
    // and plain GPL-2.0 is still GPL-2.0 (no false LGPL).
    CHECK(lic_text("GNU GENERAL PUBLIC LICENSE\n Version 2, June 1991\n") ==
          std::vector<std::string>{"GPL-2.0"});

    // New markers.
    CHECK(lic_text("Boost Software License - Version 1.0") == std::vector<std::string>{"BSL-1.0"});
    CHECK(lic_text("SIL OPEN FONT LICENSE Version 1.1") == std::vector<std::string>{"OFL-1.1"});
    CHECK(lic_text("The PNG Reference Library is supplied \"AS IS\"") ==
          std::vector<std::string>{"Libpng"});
    CHECK(lic_text("... accompanied by the Sleepycat License terms ...") ==
          std::vector<std::string>{"Sleepycat"});
    CHECK(lic_text("... dealings ... except as contained in this notice ... X Consortium ...") ==
          std::vector<std::string>{"X11"});
    CHECK(lic_text("Creative Commons Attribution 4.0 International") ==
          std::vector<std::string>{"CC-BY-4.0"});
    CHECK(lic_text("Creative Commons Attribution-ShareAlike 4.0") ==
          std::vector<std::string>{"CC-BY-SA-4.0"});
    // NCSA is BSD-3-form but must report NCSA only, not also BSD-3-Clause.
    auto ncsa = lic_text("University of Illinois/NCSA Open Source License\n"
                         "Redistribution and use in source and binary forms ... Neither the names");
    CHECK(ncsa.size() == 1 && ncsa[0] == "NCSA");
    // curl: the shared template plus the curl name.
    CHECK(lic_text("COPYRIGHT AND PERMISSION NOTICE\nCopyright (c) 1996-2024 curl authors") ==
          std::vector<std::string>{"curl"});

    // SPDX tag extraction (validated), in any file content
    auto t = lic_scan("src/foo.c", "/* SPDX-License-Identifier: GPL-2.0-or-later */\nint x;\n");
    CHECK(t.size() == 1 && t[0].type == "GPL-2.0-or-later" && t[0].category == "license");
    CHECK(t.size() == 1 && t[0].confidence == static_cast<uint8_t>(ft::Confidence::Validated));

    // SPDX tag in XML with &#xA; entities must not leak a trailing '&'.
    auto x = lic_scan("etc/NOTICE.xml",
                      "<x>SPDX-License-Identifier: MIT OR Apache-2.0 WITH LLVM-exception&#xA;more</x>");
    CHECK(!x.empty() && x[0].type == "MIT OR Apache-2.0 WITH LLVM-exception");

    // license file by name -> structural text match
    auto c = lic_scan("COPYING", "GNU GENERAL PUBLIC LICENSE\n Version 2, June 1991\n");
    CHECK(c.size() == 1 && c[0].type == "GPL-2.0" &&
          c[0].confidence == static_cast<uint8_t>(ft::Confidence::Structural));

    // a non-license file with no tag -> nothing
    CHECK(lic_scan("bin/busybox", "random\x00 bytes here").empty());

    // A decompressed NOTICE blob (basename "decompressed") is text-matched via
    // its license-named ancestor (moria's ".../NOTICE.xml.gz.extracted/...").
    auto dec = lic_scan("etc/NOTICE.xml.gz.extracted/0x0-gzip/decompressed",
                        "GNU GENERAL PUBLIC LICENSE\n Version 2, June 1991\n");
    CHECK(dec.size() == 1 && dec[0].type == "GPL-2.0" &&
          dec[0].confidence == static_cast<uint8_t>(ft::Confidence::Structural));
    // But a plain source file with license-shaped text and no license-named
    // ancestor is still not text-matched (only its SPDX tags, if any, count).
    CHECK(lic_scan("src/foo.c", "Redistribution and use in source and binary forms").empty());
}

// ---------------------------------------------------------------- sha256
// FIPS 180-4 / NIST known-answer vectors. --fetch-db relies on this to verify a
// downloaded index, so a wrong digest must be caught here.
static void test_sha256() {
    using ft::sha256_hex;
    CHECK(sha256_hex(std::string("")) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(sha256_hex(std::string("abc")) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(sha256_hex(std::string(
              "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    // A million 'a' bytes -> exercises multi-block + length padding.
    std::string million(1000000, 'a');
    CHECK(sha256_hex(million) ==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    // Padding-boundary vectors: 55 bytes is the largest that pads within one
    // block (55+1+8=64); 56 bytes forces the length into a second block; 64 is a
    // full block with all padding in the next.
    CHECK(sha256_hex(std::string(55, 'a')) ==
          "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    CHECK(sha256_hex(std::string(56, 'a')) ==
          "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
    CHECK(sha256_hex(std::string(64, 'x')) ==
          "7ce100971f64e7001e8fe5a51973ecdfe1ced42befe7ee8d5fd6219506b5393c");
}

// ---- DER private-key scanner --------------------------------------------
// kEcSec1: a real EC secp256r1 key in traditional SEC1 form (RFC 5915), DER.
static const uint8_t kEcSec1[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0xE1, 0x2B, 0xF9, 0x74, 0x95,
    0xFD, 0xA2, 0xFD, 0xA6, 0x18, 0x64, 0x56, 0x8D, 0xBE, 0xE4, 0xBF, 0x50,
    0x6F, 0x83, 0xC7, 0x7E, 0xDF, 0x25, 0xA6, 0x82, 0x32, 0x1B, 0xF6, 0x33,
    0x33, 0xB0, 0x93, 0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
    0x03, 0x01, 0x07, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x4B, 0xC0, 0xE5,
    0x07, 0x22, 0x56, 0xD9, 0xFD, 0x48, 0x45, 0xD2, 0x41, 0x76, 0x9B, 0x5D,
    0x95, 0x2B, 0xFE, 0x74, 0x8D, 0xCB, 0xA9, 0x32, 0x11, 0x55, 0xEB, 0xC5,
    0x7C, 0x73, 0xAE, 0x71, 0x1F, 0x44, 0x1C, 0x1F, 0xA9, 0x1F, 0x69, 0xC7,
    0xC1, 0xE4, 0x3E, 0x4B, 0x7B, 0x0A, 0x21, 0x60, 0x49, 0x2D, 0x63, 0x97,
    0x3C, 0x53, 0xDF, 0x8B, 0xBA, 0xA0, 0x78, 0x30, 0x2A, 0x20, 0xAD, 0xE4,
    0xEB,
};
// kEd25519: a real Ed25519 key in PKCS#8 form (RFC 8410), DER.
static const uint8_t kEd25519[] = {
    0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20, 0x73, 0xF1, 0x33, 0xEE, 0xEF, 0x15, 0x41, 0x6C,
    0x69, 0xA8, 0xDC, 0x27, 0x70, 0x58, 0x81, 0x24, 0x06, 0x48, 0x2D, 0xEB,
    0x81, 0x53, 0x21, 0x9A, 0xAE, 0x68, 0xFD, 0x35, 0x12, 0x89, 0x1D, 0x6C,
};

static void test_derkey() {
    // Two real DER keys embedded in binary padding, no PEM wrapper — exactly the
    // shape the text-anchored engine misses.
    std::vector<uint8_t> buf;
    auto pad = [&](size_t n) { for (size_t i = 0; i < n; ++i) buf.push_back(uint8_t(i * 7 + 1)); };
    pad(500);
    size_t ec_off = buf.size();
    buf.insert(buf.end(), std::begin(kEcSec1), std::end(kEcSec1));
    pad(300);
    size_t ed_off = buf.size();
    buf.insert(buf.end(), std::begin(kEd25519), std::end(kEd25519));
    pad(500);

    ft::Reader r(buf);
    auto keys = ft::scan_der_private_keys(r);
    CHECK(keys.size() == 2);
    bool ec_ok = false, ed_ok = false;
    for (const auto& k : keys) {
        CHECK(k.type == "der-private-key");
        CHECK(k.category == "secret");
        CHECK(k.confidence == static_cast<uint8_t>(ft::Confidence::Structural));
        if (k.offset == ec_off && k.size == sizeof(kEcSec1) && k.label == "EC secp256r1 private key")
            ec_ok = true;
        if (k.offset == ed_off && k.size == sizeof(kEd25519) && k.label == "Ed25519 private key")
            ed_ok = true;
    }
    CHECK(ec_ok);
    CHECK(ed_ok);

    // Negatives: key-ish class names and a lone version+SEQUENCE run must not fire.
    {
        std::string s = "org.bouncycastle.crypto.params.RSAPrivateKeyStructure loadPrivateKey";
        std::vector<uint8_t> n(s.begin(), s.end());
        ft::Reader nr(n);
        CHECK(ft::scan_der_private_keys(nr).empty());
    }
    {
        // The PKCS#8 anchor bytes but no valid key structure after them.
        std::vector<uint8_t> n = {0x00, 0x02, 0x01, 0x00, 0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x00};
        ft::Reader nr(n);
        CHECK(ft::scan_der_private_keys(nr).empty());
    }
    // Truncated key (last 5 bytes cut) must not match and must not crash.
    {
        std::vector<uint8_t> t(std::begin(kEcSec1), std::end(kEcSec1) - 5);
        ft::Reader tr(t);
        CHECK(ft::scan_der_private_keys(tr).empty());
    }
}

int main() {
    test_ahocorasick();
    test_entropy();
    test_jsonparse();
    test_detectors();
    test_false_positives();
    test_encoded();
    test_validators_github_crc();
    test_validators_jwt();
    test_validators_pem();
    test_derkey();
    test_glob();
    test_path_rules();
    test_metadata();
    test_sbom_dpkg();
    test_sbom_opkg();
    test_sbom_apk();
    test_credstore_shadow();
    test_credstore_htpasswd();
    test_credstore_dispatch();
    test_kernelcve();
    test_kallsyms();
    test_kconfig_infer();
    test_inflate();
    test_binver();
    test_kernel();
    test_uboot();
    test_filever();
    test_userrules();
    test_version();
    test_cve();
    test_nvd();
    test_rpm();
    test_langmanifest();
    test_license();
    test_sbom_emit();
    test_sha256();
    std::printf("unit: %d checks, %d failures\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
