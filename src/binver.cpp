#include "binver.hpp"

#include <algorithm>
#include <regex>
#include <string_view>
#include <utility>

#include "ahocorasick.hpp"

namespace ft {

namespace {

// A curated version-banner signature. `anchors` seed the Aho-Corasick prefilter;
// on a hit, `pattern` runs on a bounded window and its first capture group is the
// version. `cpe_vendor`/`cpe_product` co-derive the CPE for the CVE join.
struct VersionSig {
    std::string name;
    std::vector<std::string> anchors;
    std::string pattern;  // ECMAScript regex, one capture group = version
    std::string cpe_vendor;
    std::string cpe_product;
};

const std::vector<VersionSig>& sigs() {
    static const std::vector<VersionSig> s = {
        {"busybox", {"BusyBox v"}, R"(BusyBox v(\d+\.\d+\.\d+))", "busybox", "busybox"},
        {"openssl", {"OpenSSL "}, R"(OpenSSL (\d+\.\d+\.\d+[a-z]?))", "openssl", "openssl"},
        {"dropbear",
         {"Dropbear v", "Dropbear-", "dropbear_"},
         R"([Dd]ropbear[ _v-]*(\d{4}\.\d+))",
         "dropbear_ssh_project",
         "dropbear_ssh"},
        {"dnsmasq", {"Dnsmasq version "}, R"(Dnsmasq version (\d+\.\d+))", "thekelleys", "dnsmasq"},
        {"curl", {"libcurl/", "curl/"}, R"(curl/(\d+\.\d+\.\d+))", "haxx", "libcurl"},
        {"zlib", {"inflate ", "deflate "}, R"((?:in|de)flate (\d+\.\d+\.\d+))", "zlib", "zlib"},
        {"lighttpd", {"lighttpd/"}, R"(lighttpd/(\d+\.\d+\.\d+))", "lighttpd", "lighttpd"},
        {"wget", {"GNU Wget "}, R"(GNU Wget (\d+\.\d+(?:\.\d+)?))", "gnu", "wget"},
        // NOTE: no OpenSSH banner rule — dropbear/openssh embed bug-compatibility
        // version lists ("OpenSSH_3.0", "OpenSSH_7.x", …) that a banner match reads
        // as dozens of bogus versions. dropbear (the SSH in most firmware) is above.
        {"wpa_supplicant", {"wpa_supplicant v"}, R"(wpa_supplicant v(\d+\.\d+))", "w1.fi",
         "wpa_supplicant"},
        {"hostapd", {"hostapd v"}, R"(hostapd v(\d+\.\d+))", "w1.fi", "hostapd"},
        {"mosquitto", {"mosquitto version "}, R"(mosquitto version (\d+\.\d+\.\d+))", "eclipse",
         "mosquitto"},
        {"glibc", {"GNU C Library"}, R"(release version (\d+\.\d+(?:\.\d+)?))", "gnu", "glibc"},
        {"musl", {"musl libc"}, R"(Version (\d+\.\d+\.\d+))", "musl-libc", "musl"},
        // TLS/crypto libraries: single-value runtime banners in the .so/binary.
        {"mbedtls", {"mbed TLS "}, R"(mbed TLS (\d+\.\d+\.\d+))", "arm", "mbed_tls"},
        {"gnutls", {"GnuTLS "}, R"(GnuTLS (\d+\.\d+\.\d+))", "gnu", "gnutls"},
        // OpenVPN prints one version banner ("OpenVPN 2.4.7 arm-... [SSL (OpenSSL)]").
        {"openvpn", {"OpenVPN "}, R"(OpenVPN (\d+\.\d+\.\d+))", "openvpn", "openvpn"},
        // Lua's LUA_RELEASE ("Lua 5.1.5") — require all three parts so the 2-part
        // LUA_VERSION ("Lua 5.1") in the same binary is not a second component.
        // Anchor "Lua 5." excludes LuaJIT ("LuaJIT 2.x").
        {"lua", {"Lua 5."}, R"(Lua (5\.\d+\.\d+))", "lua", "lua"},
        // NOTE: no strongswan/expat banner rule — both embed symbol-version tables
        // (a full list of every release), the same trap that keeps OpenSSH out.
    };
    return s;
}

// Compiled regexes, one per sig, built once (parallel to sigs()).
const std::vector<std::regex>& compiled() {
    static const std::vector<std::regex> re = [] {
        std::vector<std::regex> v;
        for (const auto& s : sigs())
            v.emplace_back(s.pattern, std::regex::ECMAScript | std::regex::optimize);
        return v;
    }();
    return re;
}

bool is_elf(std::span<const uint8_t> d) {
    return d.size() >= 4 && d[0] == 0x7f && d[1] == 'E' && d[2] == 'L' && d[3] == 'F';
}

}  // namespace

std::vector<Component> scan_kernel_version(std::span<const uint8_t> data,
                                           const std::string& origin_path) {
    std::vector<Component> out;
    std::string_view text(reinterpret_cast<const char*>(data.data()), data.size());
    static const std::regex re(R"(Linux version (\d+\.\d+(?:\.\d+)?))",
                               std::regex::ECMAScript | std::regex::optimize);
    const std::string anchor = "Linux version ";
    std::string seen;  // dedup: the banner can appear more than once
    for (size_t p = text.find(anchor); p != std::string_view::npos;
         p = text.find(anchor, p + 1)) {
        size_t end = std::min(text.size(), p + 48);
        std::string window(text.substr(p, end - p));
        std::smatch m;
        if (!std::regex_search(window, m, re) || m.size() < 2) continue;
        std::string version = m[1].str();
        if (version == seen) continue;
        seen = version;
        Component c;
        c.name = "linux_kernel";
        c.version = version;
        c.purl = "pkg:generic/linux_kernel@" + version;
        c.cpe = "cpe:2.3:o:linux:linux_kernel:" + version + ":*:*:*:*:*:*:*";
        c.source = "kernel-banner";
        c.origin_path = origin_path;
        c.confidence = 80;
        c.evidence = "kernel banner: " + m[0].str();
        out.push_back(std::move(c));
        break;  // one kernel version per file
    }
    return out;
}

std::vector<Component> scan_uboot_version(std::span<const uint8_t> data,
                                          const std::string& origin_path) {
    std::vector<Component> out;
    std::string_view text(reinterpret_cast<const char*>(data.data()), data.size());
    // The date-scheme banner ("U-Boot 2019.04 (Apr 15 2019 - ...)") dominant since
    // 2008; capture just the "YYYY.MM" token so it matches the NVD denx:u-boot CPE
    // (a "-rc"/"-g<sha>" vendor suffix is dropped for a clean version compare).
    static const std::regex re(R"(U-Boot (20\d\d\.\d+(?:\.\d+)?))",
                               std::regex::ECMAScript | std::regex::optimize);
    const std::string anchor = "U-Boot 20";
    std::string seen;
    for (size_t p = text.find(anchor); p != std::string_view::npos;
         p = text.find(anchor, p + 1)) {
        size_t end = std::min(text.size(), p + 48);
        std::string window(text.substr(p, end - p));
        std::smatch m;
        if (!std::regex_search(window, m, re) || m.size() < 2) continue;
        std::string version = m[1].str();
        if (version == seen) continue;
        seen = version;
        Component c;
        c.name = "u-boot";
        c.version = version;
        c.purl = "pkg:generic/u-boot@" + version;
        c.cpe = "cpe:2.3:a:denx:u-boot:" + version + ":*:*:*:*:*:*:*";
        c.source = "bootloader-banner";
        c.origin_path = origin_path;
        c.confidence = 80;
        c.evidence = "bootloader banner: " + m[0].str();
        out.push_back(std::move(c));
        break;  // one u-boot version per file
    }
    return out;
}

std::vector<std::pair<std::string, std::string>> binver_cpe_products() {
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& s : sigs())
        if (!s.cpe_vendor.empty()) out.push_back({s.cpe_vendor, s.cpe_product});
    out.push_back({"denx", "u-boot"});  // scan_uboot_version (non-ELF, not in sigs())
    return out;
}

std::vector<Component> scan_binver(std::span<const uint8_t> data, const std::string& origin_path) {
    std::vector<Component> out;
    if (!is_elf(data)) return out;

    const auto& S = sigs();
    const auto& RE = compiled();

    // One automaton over all anchors; anchor id -> sig index.
    AhoCorasick ac;
    std::vector<uint32_t> id_to_sig;
    for (uint32_t si = 0; si < S.size(); ++si)
        for (const auto& a : S[si].anchors) {
            ac.add(std::vector<uint8_t>(a.begin(), a.end()), static_cast<uint32_t>(id_to_sig.size()));
            id_to_sig.push_back(si);
        }
    ac.build();

    // Bounded window for the regex (M3): version banners are short.
    constexpr size_t WINDOW = 64;
    std::vector<std::pair<std::string, std::string>> seen;  // (name, version) dedup

    ac.find(data, 0, [&](size_t off, uint32_t id) -> bool {
        uint32_t si = id_to_sig[id];
        size_t end = std::min(data.size(), off + WINDOW);
        std::string window(reinterpret_cast<const char*>(data.data()) + off, end - off);
        std::smatch m;
        if (!std::regex_search(window, m, RE[si]) || m.size() < 2) return true;
        std::string version = m[1].str();

        for (const auto& sv : seen)
            if (sv.first == S[si].name && sv.second == version) return true;  // dedup
        seen.push_back({S[si].name, version});

        Component c;
        c.name = S[si].name;
        c.version = version;
        c.purl = "pkg:generic/" + c.name + "@" + version;
        if (!S[si].cpe_vendor.empty())
            c.cpe = "cpe:2.3:a:" + S[si].cpe_vendor + ":" + S[si].cpe_product + ":" + version +
                    ":*:*:*:*:*:*:*";
        c.source = "binary-version";
        c.origin_path = origin_path;
        c.confidence = 70;  // weaker than a package-DB entry
        c.evidence = "binary version banner: " + m[0].str();
        out.push_back(std::move(c));
        return true;
    });
    return out;
}

}  // namespace ft
