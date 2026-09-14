// boot.cpp — Boot Security pass. See boot.hpp.
//
// Two artifact families:
//   1. U-Boot environment  — moria's decoded uboot-env.txt (newline-separated)
//      or a raw env region (CRC header + NUL-separated key=value list).
//   2. Device tree / FIT   — an FDT blob: /chosen bootargs, root compatible/model
//      hardware fingerprint, and FIT verified-boot posture (signatures + keys).
// The kernel command-line analyzer is shared by both (env `bootargs=` and the
// device-tree /chosen bootargs property).
#include "boot.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string_view>

#include "bootkeys.hpp"
#include "certid.hpp"
#include "fdt.hpp"
#include "reader.hpp"
#include "sha256.hpp"

namespace ft {

namespace {

// A boot finding. `sev` is [high]/[medium]/[info]; risk, separate from the
// (always-high, we-parsed-it) detection confidence.
Finding mk(const char* type, const char* sev, std::string label, std::string why,
           std::string desc, size_t off = 0) {
    Finding f;
    f.type = type;
    f.category = "boot";
    f.offset = off;
    f.label = std::move(label);
    f.description = std::move(desc);
    f.set_confidence(Confidence::Structural, std::string("[") + sev + "] " + std::move(why));
    return f;
}

bool contains(std::string_view hay, std::string_view needle) {
    return hay.find(needle) != std::string_view::npos;
}

// ---- shared kernel command-line analyzer (bootargs) ----------------------
void analyze_bootargs(std::string_view args, size_t off, std::vector<Finding>& out) {
    if (args.empty()) return;
    // Emit the full command line as context (info).
    out.push_back(mk("kernel-cmdline", "info", std::string(args),
                     "kernel command line", "boot args passed to the kernel", off));
    if (contains(args, "init=/bin/sh") || contains(args, "init=/bin/bash") ||
        contains(args, "init=/bin/busybox") || contains(args, "rdinit=/bin/sh"))
        out.push_back(mk("cmdline-init-shell", "high", std::string(args),
                         "init= spawns an interactive shell as PID 1 at boot",
                         "root shell instead of the normal init", off));
    // ` single` / ` S` / `1` runlevel style single-user boot.
    if (contains(args, " single") || contains(args, " S ") ||
        (args.size() >= 2 && args.substr(args.size() - 2) == " S"))
        out.push_back(mk("cmdline-single-user", "high", std::string(args),
                         "single-user boot mode (root shell, no auth)",
                         "single-user / maintenance mode", off));
    if (contains(args, "selinux=0") || contains(args, "enforcing=0"))
        out.push_back(mk("cmdline-selinux-off", "medium", std::string(args),
                         "SELinux disabled or set permissive on the kernel command line",
                         "mandatory access control off", off));
    if (contains(args, "androidboot.selinux=permissive"))
        out.push_back(mk("cmdline-androidboot-permissive", "medium",
                         std::string(args), "androidboot.selinux=permissive: SELinux not enforcing",
                         "Android SELinux permissive", off));
    if (contains(args, "androidboot.verifiedbootstate=orange") ||
        contains(args, "androidboot.verifiedbootstate=red") ||
        contains(args, "androidboot.verifiedbootstate=yellow"))
        out.push_back(mk("cmdline-avb-state", "medium", std::string(args),
                         "androidboot.verifiedbootstate is not green (verified boot not fully enforced)",
                         "Android Verified Boot state", off));
    if (contains(args, "earlyprintk") || contains(args, "earlycon") ||
        contains(args, " debug") || contains(args, "loglevel=8") ||
        contains(args, "ignore_loglevel"))
        out.push_back(mk("cmdline-debug", "info", std::string(args),
                         "debug / verbose-logging kernel options present",
                         "debug boot options", off));
    // A serial console is an exposed interaction surface on many devices.
    if (contains(args, "console=ttyS") || contains(args, "console=ttyAMA") ||
        contains(args, "console=ttymxc") || contains(args, "console=ttyO") ||
        contains(args, "console=ttyUSB"))
        out.push_back(mk("cmdline-serial-console", "info", std::string(args),
                         "kernel logs to a serial console (UART interaction surface)",
                         "serial console configured", off));
}

// ---- U-Boot environment ---------------------------------------------------

// Parse newline-separated `key=value` (moria's uboot-env.txt).
std::vector<std::pair<std::string, std::string>> parse_env_lines(std::span<const uint8_t> d) {
    std::vector<std::pair<std::string, std::string>> kv;
    std::string_view t(reinterpret_cast<const char*>(d.data()), d.size());
    size_t s = 0;
    while (s < t.size()) {
        size_t nl = t.find('\n', s);
        std::string_view line = t.substr(s, nl == std::string_view::npos ? t.size() - s : nl - s);
        size_t eq = line.find('=');
        if (eq != std::string_view::npos && eq > 0)
            kv.emplace_back(std::string(line.substr(0, eq)), std::string(line.substr(eq + 1)));
        if (nl == std::string_view::npos) break;
        s = nl + 1;
    }
    return kv;
}

// Parse a raw env region: try the header layouts (none / 4-byte crc / 4+1
// redundant), then a NUL-separated key=value list ending in an empty entry.
// Returns entries if it parses as an env with >= 4 well-formed vars.
std::vector<std::pair<std::string, std::string>> parse_env_raw(std::span<const uint8_t> d) {
    auto key_char = [](uint8_t c) {
        return std::isalnum(c) || c == '_';
    };
    for (size_t start : {size_t(0), size_t(4), size_t(5)}) {
        if (start >= d.size()) continue;
        std::vector<std::pair<std::string, std::string>> kv;
        size_t p = start;
        const size_t cap = std::min<size_t>(d.size(), start + (1u << 20));
        bool bad = false, terminated = false;
        while (p < cap) {
            if (d[p] == 0x00) { terminated = true; break; }  // empty entry = end
            size_t s = p;
            while (p < cap && d[p] != 0x00) ++p;
            if (p >= cap) { bad = true; break; }
            std::string_view e(reinterpret_cast<const char*>(d.data()) + s, p - s);
            size_t eq = e.find('=');
            bool ok = eq != std::string_view::npos && eq > 0;
            for (size_t i = 0; ok && i < eq; ++i)
                if (!key_char(static_cast<uint8_t>(e[i]))) ok = false;
            if (!ok) { bad = true; break; }
            kv.emplace_back(std::string(e.substr(0, eq)), std::string(e.substr(eq + 1)));
            ++p;
        }
        if (!bad && terminated && kv.size() >= 4) return kv;
    }
    return {};
}

bool name_has(const std::string& k, std::initializer_list<const char*> subs) {
    std::string lk = k;
    std::transform(lk.begin(), lk.end(), lk.begin(), [](unsigned char c) { return std::tolower(c); });
    for (const char* s : subs)
        if (lk.find(s) != std::string::npos) return true;
    return false;
}

void analyze_env(const std::vector<std::pair<std::string, std::string>>& kv,
                 std::vector<Finding>& out) {
    for (const auto& [k, v] : kv) {
        std::string kvs = k + "=" + v;
        if (k == "bootargs") {
            analyze_bootargs(v, 0, out);
        } else if (k == "bootcmd" || k == "preboot" || k == "altbootcmd") {
            out.push_back(mk("uboot-bootcmd", "info", kvs,
                             "U-Boot boot command (boot flow; may fetch over tftp/nfs)",
                             "boot command"));
        } else if (k == "bootdelay") {
            // A non-negative bootdelay lets any keypress drop to the U-Boot
            // console (an unauthenticated root-equivalent prompt).
            char* endp = nullptr;
            long n = std::strtol(v.c_str(), &endp, 10);
            if (endp && *endp == '\0' && n >= 0)
                out.push_back(mk("uboot-console-interruptible", "medium", kvs,
                                 "bootdelay >= 0: the U-Boot console can be interrupted at boot",
                                 "interruptible bootloader console"));
        } else if (name_has(k, {"passw", "secret", "token"}) ||
                   (name_has(k, {"key"}) && !name_has(k, {"keyboard"}))) {
            if (name_has(k, {"passw"}) && is_weak_password(v))
                out.push_back(mk("uboot-env-weak-password", "high", kvs,
                                 "U-Boot environment holds a weak/default bootloader password",
                                 "weak default password in env"));
            else
                out.push_back(mk("uboot-env-secret", "high", kvs,
                                 "credential / key material in the U-Boot environment",
                                 "hardcoded secret in env"));
        } else if (name_has(k, {"ethaddr", "macaddr", "wlanaddr", "hwaddr"})) {
            out.push_back(mk("uboot-env-mac", "info", kvs, "hardware MAC address",
                             "device MAC address"));
        } else if (k == "serial#" || name_has(k, {"serial", "board_sn", "sn"})) {
            out.push_back(mk("uboot-env-serial", "info", kvs, "device serial / identity",
                             "device identifier"));
        } else if (name_has(k, {"ipaddr", "serverip", "gatewayip", "netmask", "dnsip",
                                "tftp", "nfsroot", "rootpath", "bootfile"})) {
            out.push_back(mk("uboot-env-network", "info", kvs,
                             "network / provisioning configuration",
                             "network config in env"));
        }
    }
}

// ---- Device tree / FIT ----------------------------------------------------

void analyze_fdt(std::span<const uint8_t> data, std::vector<Finding>& out) {
    auto parsed = parse_fdt(data);
    if (!parsed) return;
    const auto& nodes = *parsed;

    // /chosen bootargs (the kernel command line baked into the tree).
    for (const auto& n : nodes) {
        if (n.path == "/chosen") {
            std::string args = n.str("bootargs");
            if (!args.empty()) analyze_bootargs(args, 0, out);
        }
    }

    // Hardware fingerprint from the root node.
    for (const auto& n : nodes) {
        if (n.path == "/") {
            std::string model = n.str("model");
            std::string compat = n.str("compatible");
            if (!model.empty())
                out.push_back(mk("hardware-model", "info", model, "board/device model string",
                                 "hardware fingerprint (feeds SBOM/CVE targeting)"));
            if (!compat.empty())
                out.push_back(mk("hardware-compatible", "info", compat,
                                 "SoC/board compatible string",
                                 "hardware fingerprint (feeds SBOM/CVE targeting)"));
            break;
        }
    }

    if (!fdt_is_fit(nodes)) return;

    // FIT verified-boot posture.
    size_t images = 0, signed_images = 0, hashed_images = 0;
    size_t signed_configs = 0;
    bool any_signature = false, any_required = false;
    for (const auto& n : nodes) {
        // Depth-2 nodes under /images and /configurations are the members.
        auto under = [&](const char* base) {
            std::string_view p = n.path;
            std::string_view b = base;
            return p.size() > b.size() + 1 && p.compare(0, b.size(), b) == 0 &&
                   p[b.size()] == '/' && p.find('/', b.size() + 1) == std::string_view::npos;
        };
        if (under("/images")) {
            ++images;
        } else if (under("/configurations")) {
            if (n.has("signature") || n.str("sign-images").size()) ++signed_configs;
        }
        // signature/hash subnodes (their names start with signature/hash).
        if (n.name.rfind("signature", 0) == 0) {
            any_signature = true;
            // A member (image) whose parent is /images/<x>.
            if (n.path.rfind("/images/", 0) == 0) ++signed_images;
            if (n.has("required")) any_required = true;
        }
        if (n.name.rfind("hash", 0) == 0 && n.path.rfind("/images/", 0) == 0) ++hashed_images;
        // Config-level signature subnodes.
        if (n.name.rfind("signature", 0) == 0 && n.path.rfind("/configurations/", 0) == 0) {
            any_signature = true;
            ++signed_configs;
            if (n.has("required")) any_required = true;
        }
        // Public keys under /signature.
        if (n.path.rfind("/signature/key", 0) == 0 || n.path.rfind("/signature/key-", 0) == 0) {
            std::string hint = n.str("key-name-hint");
            std::string algo = n.str("algo");
            std::string req = n.str("required");
            std::string label = hint.empty() ? n.name : hint;
            if (!algo.empty()) label += " (" + algo + ")";
            if (n.has("required")) any_required = true;
            out.push_back(mk("fit-signing-key", "info", label,
                             std::string("embedded verified-boot public key") +
                                 (req.empty() ? "" : ", required=" + req),
                             "FIT signature public key"));
        }
    }

    if (any_signature) {
        std::string s = std::to_string(signed_images) + " signed image(s), " +
                        std::to_string(signed_configs) + " signed config(s)";
        out.push_back(mk("fit-signed", "info", s, "FIT carries signature nodes (verified boot)",
                         "verified-boot signatures present"));
        if (!any_required)
            out.push_back(mk("fit-signature-not-enforced", "medium", s,
                             "signatures present but no key/config marked required; "
                             "U-Boot may still boot an unsigned image",
                             "verified boot not enforced"));
    } else if (images > 0) {
        std::string s = std::to_string(images) + " image(s), " + std::to_string(hashed_images) +
                        " with a hash, none signed";
        out.push_back(mk("fit-unsigned", "medium", s,
                         "FIT image has no signature nodes: no verified boot (images can be swapped)",
                         "no verified boot"));
    }
}

// ---- Android Verified Boot (AVB) vbmeta -----------------------------------

const char* avb_algo(uint64_t a) {
    switch (a) {
        case 0: return "NONE";
        case 1: return "SHA256_RSA2048";
        case 2: return "SHA256_RSA4096";
        case 3: return "SHA256_RSA8192";
        case 4: return "SHA512_RSA2048";
        case 5: return "SHA512_RSA4096";
        case 6: return "SHA512_RSA8192";
        default: return "unknown";
    }
}

// A NUL/fixed-length ASCII field printed safely (control bytes dropped).
std::string clean_ascii(std::span<const uint8_t> b) {
    std::string s;
    for (uint8_t c : b) {
        if (c == 0) break;
        if (c >= 0x20 && c <= 0x7E) s.push_back(static_cast<char>(c));
    }
    return s;
}

void analyze_vbmeta(std::span<const uint8_t> data, std::vector<Finding>& out) {
    Reader r(data);
    auto u32 = [&](size_t o) { return r.at<uint32_t>(o, Endian::Big); };
    auto u64 = [&](size_t o) { return r.at<uint64_t>(o, Endian::Big); };

    auto auth = u64(12), aux = u64(20);
    auto algo32 = u32(28);
    auto pk_off = u64(64), pk_size = u64(72);
    auto desc_off = u64(96), desc_size = u64(104);
    auto rollback = u64(112);
    auto flags = u32(120);
    if (!auth || !aux || !algo32 || !pk_off || !pk_size || !desc_off || !desc_size || !flags ||
        !rollback)
        return;
    // Consistency gate (rejects a stray "AVB0" in arbitrary data): the header +
    // authentication + auxiliary blocks must fit, and the key/descriptor slices
    // must lie inside the auxiliary block.
    if (*auth > (16u << 20) || *aux > (16u << 20)) return;
    if (256 + *auth + *aux > data.size()) return;
    if (*pk_off + *pk_size > *aux || *desc_off + *desc_size > *aux) return;
    const uint64_t f = *flags;
    const uint64_t alg = *algo32;

    // Verification posture from the header flags (top-level vbmeta only).
    if (f & 0x2)
        out.push_back(mk("avb-verification-disabled", "high", "flags=0x2",
                         "AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED: all verified boot is off",
                         "verified boot disabled"));
    if (f & 0x1)
        out.push_back(mk("avb-hashtree-disabled", "high", "flags=0x1",
                         "AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED: dm-verity integrity checking is off",
                         "dm-verity disabled"));
    if (alg == 0)
        out.push_back(mk("avb-unsigned", "high", "algorithm=NONE",
                         "vbmeta is not signed (algorithm NONE): the root of trust is unauthenticated",
                         "unsigned vbmeta"));
    else
        out.push_back(mk("avb-signed", "info", std::string(avb_algo(alg)),
                         "vbmeta signed, rollback index " + std::to_string(*rollback),
                         "verified-boot signature"));

    // Signing-key fingerprint (SHA-256 of the AVB public-key blob in the aux
    // block). Matching it against a known/test-key set lands with the corpus.
    const uint64_t aux_base = 256 + *auth;
    if (*pk_size > 0) {
        if (auto pk = r.bytes(aux_base + *pk_off, *pk_size)) {
            std::string fp = sha256_hex(*pk).substr(0, 32);
            if (const KnownKey* kt = known_signing_key(fp))
                out.push_back(mk("avb-test-key", "high", std::string("key = ") + kt->label,
                                 std::string("AVB is signed with a known test key; its private key is "
                                             "public (") + kt->ref + "), so verified boot can be forged",
                                 "test signing key in production"));
            else
                out.push_back(mk("avb-signing-key", "info", "sha256:" + fp,
                                 "AVB signing public key (fingerprint)", "verified-boot signing key"));
        }
    }

    // Descriptors (aux block). Each AvbDescriptor is { u64 tag; u64 nbf; payload }.
    const uint64_t db = aux_base + *desc_off;
    uint64_t p = db;
    const uint64_t dend = db + *desc_size;
    for (int i = 0; i < 512 && p + 16 <= dend; ++i) {
        auto tag = r.at<uint64_t>(p, Endian::Big);
        auto nbf = r.at<uint64_t>(p + 8, Endian::Big);
        if (!tag || !nbf) break;
        const uint64_t body = p + 16;
        if (*nbf > dend - body) break;  // runs past the descriptors block
        switch (*tag) {
            case 1: {  // hashtree (dm-verity)
                auto pnlen = r.at<uint32_t>(body + 88, Endian::Big);
                auto algb = r.bytes(body + 56, 32);
                if (pnlen && algb) {
                    auto pn = r.bytes(body + 164, *pnlen);
                    std::string name = pn ? clean_ascii(*pn) : "";
                    out.push_back(mk("avb-dm-verity", "info", name + " (" + clean_ascii(*algb) + ")",
                                     "dm-verity hashtree over partition '" + name + "'",
                                     "verified partition"));
                }
                break;
            }
            case 4: {  // chain partition (delegated key + rollback location)
                auto ril = r.at<uint32_t>(body, Endian::Big);
                auto pnlen = r.at<uint32_t>(body + 4, Endian::Big);
                if (ril && pnlen) {
                    auto pn = r.bytes(body + 76, *pnlen);  // rollback+lens+flags(16) + reserved(60)
                    std::string name = pn ? clean_ascii(*pn) : "";
                    out.push_back(mk("avb-chain-partition", "info",
                                     name + " (rollback loc " + std::to_string(*ril) + ")",
                                     "partition '" + name + "' is chained to its own key",
                                     "chained partition"));
                }
                break;
            }
            case 3: {  // kernel cmdline (injected by AVB)
                auto clen = r.at<uint32_t>(body + 4, Endian::Big);
                if (clen) {
                    auto cb = r.bytes(body + 68, *clen);
                    if (cb) analyze_bootargs(clean_ascii(*cb), body + 68, out);
                }
                break;
            }
            default: break;  // property / hash / unknown
        }
        p = body + *nbf;
    }
}

// ---- x86 UEFI Secure Boot variables ---------------------------------------

// On-disk EFI_GUID byte layouts.
constexpr uint8_t kAuthVarStore[16] = {0x78, 0x2C, 0xF3, 0xAA, 0x7B, 0x94, 0x9A, 0x43,
                                       0xA1, 0x80, 0x2E, 0x14, 0x4E, 0xC3, 0x77, 0x92};
constexpr uint8_t kVarStore[16] = {0x16, 0x36, 0xCF, 0xDD, 0x75, 0x32, 0x64, 0x41,
                                   0x98, 0xB6, 0xFE, 0x85, 0x70, 0x7F, 0xFE, 0x7D};
constexpr uint8_t kGlobalVar[16] = {0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11,
                                    0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C};
constexpr uint8_t kImageSecDb[16] = {0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45,
                                     0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F};

// EFI_SIGNATURE_LIST signature-type GUIDs (on-disk bytes). A PK/KEK/db/dbx
// variable's data is one or more concatenated lists of one of these types.
constexpr uint8_t kCertX509[16]    = {0xA1, 0x59, 0xC0, 0xA5, 0xE4, 0x94, 0xA7, 0x4A,
                                      0x87, 0xB5, 0xAB, 0x15, 0x5C, 0x2B, 0xF0, 0x72};
constexpr uint8_t kCertSha256[16]  = {0x26, 0x16, 0xC4, 0xC1, 0x4C, 0x50, 0x92, 0x40,
                                      0xAC, 0xA9, 0x41, 0xF9, 0x36, 0x93, 0x43, 0x28};
constexpr uint8_t kCertSha1[16]    = {0x12, 0xA5, 0x6C, 0x82, 0x10, 0xCF, 0xC9, 0x4A,
                                      0xB1, 0x87, 0xBE, 0x01, 0x49, 0x66, 0x31, 0xBD};
constexpr uint8_t kCertRsa2048[16] = {0xE8, 0x66, 0x57, 0x3C, 0x9C, 0x26, 0x34, 0x4E,
                                      0xAA, 0x14, 0xED, 0x77, 0x6E, 0x85, 0xB3, 0xB6};

uint32_t le32_at(std::span<const uint8_t> d, size_t o) {
    return uint32_t(d[o]) | (uint32_t(d[o + 1]) << 8) | (uint32_t(d[o + 2]) << 16) |
           (uint32_t(d[o + 3]) << 24);
}
bool guid_at(std::span<const uint8_t> d, size_t off, const uint8_t g[16]) {
    return off + 16 <= d.size() && std::equal(g, g + 16, d.begin() + off);
}
bool is_cert_type_guid(std::span<const uint8_t> d, size_t off) {
    return guid_at(d, off, kCertX509) || guid_at(d, off, kCertSha256) ||
           guid_at(d, off, kCertSha1) || guid_at(d, off, kCertRsa2048);
}

size_t find_bytes(std::span<const uint8_t> hay, const uint8_t* pat, size_t patlen, size_t from) {
    if (patlen == 0 || hay.size() < patlen) return std::string::npos;
    const void* p = memmem(hay.data() + from, hay.size() - from, pat, patlen);
    return p ? static_cast<size_t>(static_cast<const uint8_t*>(p) - hay.data()) : std::string::npos;
}

// Decode a UEFI variable name (UTF-16LE) to ASCII (control/high bytes dropped).
std::string utf16_name(std::span<const uint8_t> b) {
    std::string s;
    for (size_t i = 0; i + 1 < b.size(); i += 2) {
        uint16_t c = b[i] | (b[i + 1] << 8);
        if (c == 0) break;
        if (c >= 0x20 && c < 0x7F) s.push_back(static_cast<char>(c));
    }
    return s;
}

// Inventory of one or more concatenated EFI_SIGNATURE_LISTs: entry counts per
// type and the DER bytes of each X.509 certificate.
struct SigListInfo {
    bool well_formed = false;
    size_t x509 = 0, sha256 = 0, sha1 = 0, rsa2048 = 0;
    std::vector<std::vector<uint8_t>> x509_certs;
    size_t revocations() const { return x509 + sha256 + sha1 + rsa2048; }
};

SigListInfo parse_siglists(std::span<const uint8_t> d) {
    SigListInfo si;
    size_t pos = 0;
    for (int i = 0; i < 4096 && pos + 28 <= d.size(); ++i) {
        if (!is_cert_type_guid(d, pos)) break;  // not (or no longer) a signature list
        const size_t list_size = le32_at(d, pos + 16);
        const size_t hdr = le32_at(d, pos + 20);
        const size_t sig_size = le32_at(d, pos + 24);
        if (list_size < 28 + hdr || sig_size <= 16 || list_size > d.size() - pos ||
            sig_size > list_size)
            break;
        si.well_formed = true;
        const size_t nsig = (list_size - 28 - hdr) / sig_size;
        if (guid_at(d, pos, kCertX509)) {
            size_t e = pos + 28 + hdr;
            for (size_t k = 0; k < nsig && e + sig_size <= pos + list_size; ++k) {
                const size_t coff = e + 16, clen = sig_size - 16;  // skip owner GUID
                if (coff + clen <= d.size())
                    si.x509_certs.emplace_back(d.begin() + coff, d.begin() + coff + clen);
                e += sig_size;
            }
            si.x509 += nsig;
        } else if (guid_at(d, pos, kCertSha256)) si.sha256 += nsig;
        else if (guid_at(d, pos, kCertSha1)) si.sha1 += nsig;
        else si.rsa2048 += nsig;
        pos += list_size;
    }
    return si;
}

// Check each X.509 cert in a list against the compiled-in test/default signing-key
// corpus (PKFAIL etc.). Emits a high finding per hit; sets `first_fp` to the first
// cert's fingerprint (for the single-anchor correlation). Returns true on a hit.
bool check_siglist_test_keys(const SigListInfo& si, const char* role, std::vector<Finding>& out,
                             std::string& first_fp) {
    bool hit = false;
    for (const auto& der : si.x509_certs) {
        std::string fp = cert_fingerprint(der);
        if (first_fp.empty()) first_fp = fp;
        if (const KnownKey* kt = known_cert(fp)) {
            hit = true;
            const char* type = std::string(role) == "PK" ? "uefi-test-platform-key" : "uefi-test-key";
            out.push_back(mk(type, "high", std::string(role) + " = " + kt->label,
                             std::string("UEFI ") + role + " contains a known test/default key (" +
                                 kt->label + "); its private key is public (" + kt->ref +
                                 "), so the Secure Boot chain is forgeable (PKFAIL)",
                             "test/default key in " + std::string(role)));
        }
    }
    return hit;
}

// The recovered Secure Boot variables (from whichever store format).
struct SbVars {
    int setup_mode = -1, secure_boot = -1;
    bool pk = false, kek = false, db = false, dbx = false;
    size_t pk_off = 0, pk_len = 0, kek_off = 0, kek_len = 0;
    size_t db_off = 0, db_len = 0, dbx_off = 0, dbx_len = 0;
    bool any() const { return pk || kek || db || dbx || setup_mode >= 0 || secure_boot >= 0; }
};

// EDK2 / OVMF authenticated variable store (AUTHENTICATED_VARIABLE_HEADER, 0x55AA).
void walk_edk2_store(std::span<const uint8_t> data, size_t store, SbVars& v) {
    Reader r(data);
    auto fmt = r.at<uint8_t>(store + 20, Endian::Little);  // VARIABLE_STORE_HEADER format byte
    if (!fmt || *fmt != 0x5A) return;
    size_t p = store + 28;
    const size_t end = data.size();
    for (int i = 0; i < 8192 && p + 60 <= end; ++i) {
        auto start_id = r.at<uint16_t>(p, Endian::Little);
        if (!start_id || *start_id != 0x55AA) break;
        auto state = r.at<uint8_t>(p + 2, Endian::Little);
        auto name_size = r.at<uint32_t>(p + 36, Endian::Little);
        auto data_size = r.at<uint32_t>(p + 40, Endian::Little);
        auto vguid = r.bytes(p + 44, 16);
        if (!state || !name_size || !data_size || !vguid) break;
        const size_t name_at = p + 60, data_at = name_at + *name_size;
        if (*name_size > (4u << 10) || *data_size > (16u << 20) || data_at + *data_size > end) break;
        if (*state == 0x3F) {  // VAR_ADDED (live)
            std::string name = utf16_name(*r.bytes(name_at, *name_size));
            const bool global = std::equal(kGlobalVar, kGlobalVar + 16, vguid->begin());
            const bool imgsec = std::equal(kImageSecDb, kImageSecDb + 16, vguid->begin());
            auto val1 = [&]() -> int {
                auto x = r.at<uint8_t>(data_at, Endian::Little);
                return x ? *x : -1;
            };
            if (global && name == "SetupMode") v.setup_mode = val1();
            else if (global && name == "SecureBoot") v.secure_boot = val1();
            else if (global && name == "PK") { v.pk = true; v.pk_off = data_at; v.pk_len = *data_size; }
            else if (global && name == "KEK") { v.kek = true; v.kek_off = data_at; v.kek_len = *data_size; }
            else if (imgsec && name == "db") { v.db = true; v.db_off = data_at; v.db_len = *data_size; }
            else if (imgsec && name == "dbx") { v.dbx = true; v.dbx_off = data_at; v.dbx_len = *data_size; }
        }
        size_t next = (data_at + *data_size + 3) & ~size_t(3);
        if (next <= p) break;
        p = next;
    }
}

// AMI NVAR variable store (what most vendor BIOSes use, not the EDK2 format).
// Entry header: 'NVAR'(4), size(u16 LE), next(3), attributes(u8). Attribute bits:
// VALID 0x80, ASCII_NAME 0x02, GUID_INLINE 0x04, DATA_ONLY 0x08. After the header
// comes a 16-byte inline GUID or a 1-byte GUID-store index, then the (ASCII/UCS2)
// name, then the variable data (an EFI_SIGNATURE_LIST for PK/KEK/db/dbx). The
// latest valid entry for a name wins; the siglist parser self-bounds, so the
// trailing extended-header/auth metadata of the entry is harmless.
void walk_nvar_store(std::span<const uint8_t> data, SbVars& v) {
    static const uint8_t kNvar[4] = {'N', 'V', 'A', 'R'};
    size_t base = find_bytes(data, kNvar, 4, 0);
    if (base == std::string::npos) return;
    const size_t end = data.size();
    size_t pos = base;
    for (int i = 0; i < 65536 && pos + 10 <= end; ++i) {
        if (!(data[pos] == 'N' && data[pos + 1] == 'V' && data[pos + 2] == 'A' &&
              data[pos + 3] == 'R')) { ++pos; continue; }
        const uint16_t size = uint16_t(data[pos + 4]) | (uint16_t(data[pos + 5]) << 8);
        const uint8_t attr = data[pos + 9];
        if (size < 11 || size == 0xFFFF || pos + size > end) { ++pos; continue; }
        if ((attr & 0x80) && !(attr & 0x08)) {  // valid, carries a name (not data-only)
            const size_t goff = pos + 10 + ((attr & 0x04) ? 16 : 1);
            std::string name;
            size_t j = goff;
            if (attr & 0x02) {  // ASCII name
                while (j < pos + size && data[j]) {
                    if (data[j] >= 0x20 && data[j] < 0x7F) name.push_back(char(data[j]));
                    ++j;
                }
                ++j;  // NUL
            } else {  // UCS2 name
                while (j + 1 < pos + size && (data[j] || data[j + 1])) {
                    uint16_t c = data[j] | (data[j + 1] << 8);
                    if (c >= 0x20 && c < 0x7F) name.push_back(char(c));
                    j += 2;
                }
                j += 2;
            }
            const size_t data_off = j;
            if (data_off <= pos + size) {
                const size_t dlen = pos + size - data_off;
                if (name == "PK") { v.pk = true; v.pk_off = data_off; v.pk_len = dlen; }
                else if (name == "KEK") { v.kek = true; v.kek_off = data_off; v.kek_len = dlen; }
                else if (name == "db") { v.db = true; v.db_off = data_off; v.db_len = dlen; }
                else if (name == "dbx") { v.dbx = true; v.dbx_off = data_off; v.dbx_len = dlen; }
                else if (name == "SetupMode" && data_off < end) v.setup_mode = data[data_off];
                else if (name == "SecureBoot" && data_off < end) v.secure_boot = data[data_off];
            }
        }
        pos += size;
    }
}

// Emit the Secure Boot posture findings from recovered variables.
void emit_sb_posture(std::span<const uint8_t> data, const SbVars& v, std::vector<Finding>& out) {
    Reader r(data);
    auto listof = [&](size_t off, size_t len) -> SigListInfo {
        auto b = r.bytes(off, len);
        return b ? parse_siglists(*b) : SigListInfo{};
    };

    if (v.secure_boot == 0)
        out.push_back(mk("uefi-secureboot-off", "high", "SecureBoot=0",
                         "UEFI Secure Boot is disabled", "secure boot off"));
    if (v.setup_mode == 1 || !v.pk)
        out.push_back(mk("uefi-setup-mode", "high", v.pk ? "SetupMode=1" : "no PK",
                         "Secure Boot is in Setup Mode / no Platform Key: arbitrary keys can be enrolled",
                         "no platform key enrolled"));

    std::string pk_fp, kek_fp, db_fp;
    if (v.pk) {
        SigListInfo si = listof(v.pk_off, v.pk_len);
        if (!check_siglist_test_keys(si, "PK", out, pk_fp)) {
            if (pk_fp.empty() && v.pk_len)  // no X.509 cert parsed: fingerprint the raw data
                if (auto b = r.bytes(v.pk_off, v.pk_len)) pk_fp = sha256_hex(*b).substr(0, 32);
            out.push_back(mk("uefi-platform-key", "info", pk_fp.empty() ? "PK" : "PK cert sha256:" + pk_fp,
                             "UEFI Platform Key enrolled", "platform key"));
        }
    }
    if (v.kek) { SigListInfo si = listof(v.kek_off, v.kek_len); check_siglist_test_keys(si, "KEK", out, kek_fp); }
    if (v.db)  { SigListInfo si = listof(v.db_off, v.db_len);   check_siglist_test_keys(si, "db", out, db_fp); }

    if (v.secure_boot == 1 && v.pk)
        out.push_back(mk("uefi-secureboot-on", "info",
                         std::string("SecureBoot=1") + (v.kek ? ", KEK present" : ""),
                         "UEFI Secure Boot enabled with a Platform Key", "secure boot on"));
    else if (v.pk && v.secure_boot < 0)
        out.push_back(mk("uefi-secureboot-on", "info",
                         std::string("PK enrolled") + (v.kek ? ", KEK present" : "") +
                             (v.db ? ", db present" : ""),
                         "Secure Boot is provisioned (Platform Key enrolled); runtime SecureBoot "
                         "state is not stored in the image", "secure boot provisioned"));

    // A single certificate serving as PK, the only KEK, and the only db entry is a
    // single point of compromise for the whole chain.
    if (!pk_fp.empty() && pk_fp == kek_fp && pk_fp == db_fp)
        out.push_back(mk("uefi-single-anchor", "medium", "PK = KEK = db",
                         "the same certificate is the Platform Key, the sole KEK, and the sole db "
                         "entry: one key anchors the entire Secure Boot chain (single point of compromise)",
                         "single-key secure boot chain"));

    // dbx currency (gap: enumerate revocations, not just size).
    if (v.dbx) {
        SigListInfo si = listof(v.dbx_off, v.dbx_len);
        size_t revs = si.revocations();
        if (!si.well_formed || revs == 0)
            out.push_back(mk("uefi-dbx-empty", "medium", "dbx empty",
                             "the revocation database (dbx) is empty: known-bad bootloaders are not revoked",
                             "no dbx revocations"));
        else
            out.push_back(mk("uefi-dbx", "info", "dbx: " + std::to_string(revs) + " revocation(s)",
                             "dbx revocation database present (" + std::to_string(revs) +
                                 " entr" + (revs == 1 ? "y" : "ies") + ")", "dbx revocations"));
    } else if (v.db || v.pk) {
        out.push_back(mk("uefi-dbx-empty", "medium", "no dbx",
                         "no revocation database (dbx): known-bad bootloaders are not revoked",
                         "no dbx revocations"));
    }
}

// Analyze a UEFI firmware image / variable-store region. Tries the EDK2 store
// first, then the AMI NVAR store (most vendor BIOSes), then emits posture.
void analyze_uefi(std::span<const uint8_t> data, std::vector<Finding>& out) {
    SbVars v;
    size_t store = find_bytes(data, kAuthVarStore, 16, 0);
    if (store == std::string::npos) store = find_bytes(data, kVarStore, 16, 0);
    if (store != std::string::npos) walk_edk2_store(data, store, v);
    if (!v.any()) walk_nvar_store(data, v);  // fall back to the AMI NVAR format
    if (!v.any()) return;
    emit_sb_posture(data, v, out);
}

// Analyze a standalone EFI_SIGNATURE_LIST file (an extracted Secure Boot variable
// — PK/KEK/db/dbx from UEFITool/chipsec). Reports its inventory and any test/
// default signing-key hit; the key-weakness pass covers the certs' key strength.
void analyze_siglist_file(const SigListInfo& si, std::vector<Finding>& out) {
    std::string counts;
    auto add = [&](size_t n, const std::string& sing, const std::string& plur) {
        if (!n) return;
        if (!counts.empty()) counts += ", ";
        counts += std::to_string(n) + " " + (n == 1 ? sing : plur);
    };
    add(si.x509, "X.509 cert", "X.509 certs");
    add(si.sha256, "SHA-256 hash", "SHA-256 hashes");
    add(si.sha1, "SHA-1 hash", "SHA-1 hashes");
    add(si.rsa2048, "RSA-2048 key", "RSA-2048 keys");
    if (counts.empty()) counts = "0 entries";
    out.push_back(mk("uefi-siglist", "info", counts,
                     "UEFI Secure Boot signature list (" + counts + ")", "efi signature list"));
    std::string fp;
    check_siglist_test_keys(si, "signature list", out, fp);
}

}  // namespace

std::vector<Finding> scan_boot(const std::string& path, std::span<const uint8_t> data) {
    std::vector<Finding> out;
    if (data.empty()) return out;

    // Basename for path-based dispatch.
    std::string_view p = path;
    size_t slash = p.find_last_of('/');
    std::string_view base = slash == std::string_view::npos ? p : p.substr(slash + 1);

    // 1. U-Boot environment.
    if (base == "uboot-env.txt") {
        analyze_env(parse_env_lines(data), out);
        return out;
    }

    // 2. AVB vbmeta ("AVB0" magic at offset 0).
    if (data.size() >= 256 && data[0] == 'A' && data[1] == 'V' && data[2] == 'B' &&
        data[3] == '0') {
        analyze_vbmeta(data, out);
        return out;
    }

    // 3. Device tree / FIT (FDT magic at offset 0).
    if (data.size() >= 4 && data[0] == 0xD0 && data[1] == 0x0D && data[2] == 0xFE &&
        data[3] == 0xED) {
        analyze_fdt(data, out);
        return out;
    }

    // 4. x86 UEFI firmware image (Secure Boot variables). The FV header signature
    //    "_FVH" sits at +40 of each firmware volume: at offset 40 for an image
    //    that begins with an FV, but deeper in a full-flash / descriptor-prefixed
    //    SPI dump (the low region is often padding). Search for it (bounded to the
    //    first 64 MB — larger files are not BIOS images) and route to the UEFI
    //    analyzer, which self-filters (emits nothing without a real variable store).
    {
        static const uint8_t kFvh[4] = {'_', 'F', 'V', 'H'};
        std::span<const uint8_t> head = data.subspan(0, std::min<size_t>(data.size(), 64u << 20));
        if (find_bytes(head, kFvh, 4, 0) != std::string::npos) {
            analyze_uefi(data, out);
            if (!out.empty()) return out;
        }
    }

    // 4b. A standalone EFI_SIGNATURE_LIST: an extracted Secure Boot variable
    //     (PK/KEK/db/dbx from UEFITool/chipsec). Its content begins with a
    //     signature-type GUID and parses as a well-formed list.
    if (data.size() >= 28 && is_cert_type_guid(data, 0)) {
        SigListInfo si = parse_siglists(data);
        if (si.well_formed) {
            analyze_siglist_file(si, out);
            return out;
        }
    }

    // 5. Android/OTA code-signing certificate: an APK/OTA PKCS#7 signature block
    //    (META-INF/*.RSA|DSA|EC) or a raw X.509 cert. Flag only a corpus match (a
    //    known test signing cert whose private key is public) to stay low-noise.
    {
        auto ends = [&](std::string_view s) {
            return base.size() >= s.size() &&
                   base.compare(base.size() - s.size(), s.size(), s) == 0;
        };
        std::vector<uint8_t> cert;
        if (ends(".RSA") || ends(".DSA") || ends(".EC"))
            cert = cert_from_pkcs7(data);
        else if (ends(".x509.pem") || ends(".crt") || ends(".cer") || ends(".der") || ends(".pem"))
            cert = cert_from_any(data);
        if (!cert.empty()) {
            if (const KnownKey* kt = known_cert(cert_fingerprint(cert))) {
                out.push_back(mk("apk-test-signing-cert", "high", std::string("cert = ") + kt->label,
                                 std::string("code-signing certificate is a known test key; its "
                                             "private key is public (") + kt->ref +
                                     "), so apps/OTAs can be signed as trusted",
                                 "test code-signing cert"));
                return out;
            }
        }
    }

    // 6. A raw env region (NUL-separated key=value list). Bounded, low-FP: needs
    //    >= 4 well-formed vars ending in an empty entry.
    if (auto kv = parse_env_raw(data); !kv.empty()) {
        analyze_env(kv, out);
        return out;
    }

    return out;
}

}  // namespace ft
