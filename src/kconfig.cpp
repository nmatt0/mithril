#include "kconfig.hpp"

#include <string_view>

#include "inflate.hpp"

namespace ft {

std::optional<std::string> extract_kconfig(std::span<const uint8_t> data) {
    std::string_view sv(reinterpret_cast<const char*>(data.data()), data.size());
    size_t st = sv.find("IKCFG_ST");
    if (st == std::string_view::npos) return std::nullopt;
    size_t gz = st + 8;  // gzip stream begins right after the marker
    if (gz + 2 > data.size() || data[gz] != 0x1f || static_cast<uint8_t>(data[gz + 1]) != 0x8b)
        return std::nullopt;
    size_t ed = sv.find("IKCFG_ED", gz);
    size_t end = (ed == std::string_view::npos) ? data.size() : ed;
    auto inf = gzip_inflate(data.subspan(gz, end - gz), 32u << 20);
    if (!inf) return std::nullopt;
    return std::string(inf->begin(), inf->end());
}

std::set<std::string> kconfig_enabled_options(const std::string& cfg) {
    std::set<std::string> out;
    size_t p = 0;
    // treat the start-of-string as a line start too
    std::string hay = "\n" + cfg;
    while ((p = hay.find("\nCONFIG_", p)) != std::string::npos) {
        size_t name_start = p + 1;  // skip '\n'
        size_t eq = hay.find('=', name_start);
        size_t nl = hay.find('\n', name_start);
        if (eq != std::string::npos && (nl == std::string::npos || eq < nl) && eq + 1 < hay.size() &&
            (hay[eq + 1] == 'y' || hay[eq + 1] == 'm'))
            out.insert(hay.substr(name_start, eq - name_start));
        p = name_start;
    }
    return out;
}

Finding kconfig_finding(const std::string& cfg) {
    std::set<std::string> en = kconfig_enabled_options(cfg);
    auto set = [&](const char* opt) { return en.find(opt) != en.end(); };
    std::string hard;
    auto note = [&](const char* label, const char* opt) {
        hard += hard.empty() ? "" : " ";
        hard += std::string(label) + (set(opt) ? "+" : "-");
    };
    note("stackprot", "CONFIG_STACKPROTECTOR");
    note("fortify", "CONFIG_FORTIFY_SOURCE");
    note("kaslr", "CONFIG_RANDOMIZE_BASE");
    note("bpf_unpriv", "CONFIG_BPF_UNPRIV_DEFAULT_OFF");

    Finding f;
    f.offset = 0;
    f.type = "kernel-config";
    f.category = "config";
    f.label = std::to_string(en.size()) + " options";
    f.description = "Embedded kernel .config (CONFIG_IKCONFIG); hardening: " + hard + ".";
    f.set_confidence(Confidence::Structural, "IKCONFIG (IKCFG_ST) inflated");
    return f;
}

std::vector<Finding> scan_kconfig(const std::string& relpath, std::span<const uint8_t> data) {
    (void)relpath;
    auto cfg = extract_kconfig(data);
    if (!cfg) return {};
    return {kconfig_finding(*cfg)};
}

}  // namespace ft
