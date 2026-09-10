#include "report.hpp"

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <iterator>
#include <optional>
#include <string_view>
#include <thread>
#include <unordered_set>

#include "binver.hpp"
#include "credstore.hpp"
#include "derkey.hpp"
#include "engine.hpp"
#include "file_map.hpp"
#include "filever.hpp"
#include "kallsyms.hpp"
#include "kconfig.hpp"
#include "kconfig_infer.hpp"
#include "langmanifest.hpp"
#include "license.hpp"
#include "reader.hpp"
#include "rpm.hpp"
#include "rules_builtin.hpp"
#include "sbom.hpp"

namespace ft {

namespace fs = std::filesystem;

namespace {

struct FileHits {
    std::string path;
    size_t size = 0;
    bool ok = true;
    std::string error;
    std::vector<Finding> secrets;    // content findings, category "secret"
    std::vector<Finding> notable;    // path-rule findings
    std::vector<Component> components;
    std::vector<Finding> licenses;
    std::string distro_id, distro_version;  // parsed if this file is os-release
    bool has_kconfig = false;
    KernelConfigView kcv;  // per-file config knowledge (merged into the report)
    std::string kconfig_text, kconfig_source;  // verbatim recovered .config, if any
};

// Parse an os-release file for ID and VERSION_ID (quotes stripped).
void parse_os_release(std::span<const uint8_t> data, std::string& id, std::string& version) {
    std::string_view text(reinterpret_cast<const char*>(data.data()), data.size());
    size_t start = 0;
    while (start <= text.size()) {
        size_t nl = text.find('\n', start);
        std::string_view line =
            text.substr(start, nl == std::string_view::npos ? std::string_view::npos : nl - start);
        auto val = [&](std::string_view key) -> std::string {
            if (line.rfind(key, 0) != 0) return {};
            std::string_view v = line.substr(key.size());
            if (!v.empty() && (v.front() == '"' || v.front() == '\'')) v.remove_prefix(1);
            if (!v.empty() && (v.back() == '"' || v.back() == '\'' || v.back() == '\r'))
                v.remove_suffix(1);
            return std::string(v);
        };
        if (std::string v = val("ID="); !v.empty()) id = v;
        if (std::string v = val("VERSION_ID="); !v.empty()) version = v;
        if (nl == std::string_view::npos) break;
        start = nl + 1;
    }
}

FileHits scan_one(const fs::path& path, const fs::path& root, const Passes& passes,
                  const Engine* engine) {
    FileHits fh;
    std::error_code ec;
    fh.path = fs::relative(path, root, ec).string();
    if (fh.path.empty()) fh.path = path.string();

    // Path rules (M1) don't need the file contents; run them first.
    if (engine) fh.notable = engine->scan_paths(fh.path, 0);

    FileMap fm;
    if (!fm.open(path.string())) {
        fh.ok = false;
        fh.error = fm.error();
        return fh;
    }
    fh.size = fm.size();
    // Backfill the size on any path-rule findings now that we have it.
    for (auto& f : fh.notable) f.size = fh.size;

    Reader reader(fm.span());
    if (engine) fh.secrets = engine->scan_content(reader);  // M2/M3 (built-in + user rules)
    if (passes.secrets) {
        // M4 credential stores (shadow/htpasswd) ride the secrets pass.
        auto creds = scan_credstores(fh.path, fm.span());
        fh.secrets.insert(fh.secrets.end(), std::make_move_iterator(creds.begin()),
                          std::make_move_iterator(creds.end()));
        // Raw DER private keys embedded in binary firmware (no PEM wrapper), which
        // the text-anchored content engine cannot see. Scans the whole buffer.
        auto derkeys = scan_der_private_keys(reader);
        fh.secrets.insert(fh.secrets.end(), std::make_move_iterator(derkeys.begin()),
                          std::make_move_iterator(derkeys.end()));
    }
    if (passes.sbom) {
        fh.components = scan_sbom(fh.path, fm.span());  // M4 package DBs
        auto bv = scan_binver(fm.span(), fh.path);      // binary version strings (ELF only)
        fh.components.insert(fh.components.end(), std::make_move_iterator(bv.begin()),
                             std::make_move_iterator(bv.end()));
        auto lm = scan_langmanifest(fh.path, fm.span());  // language manifests/lockfiles
        fh.components.insert(fh.components.end(), std::make_move_iterator(lm.begin()),
                             std::make_move_iterator(lm.end()));
        auto rp = scan_rpm(fh.path, fm.span());  // rpm database
        fh.components.insert(fh.components.end(), std::make_move_iterator(rp.begin()),
                             std::make_move_iterator(rp.end()));
        auto fv = scan_filename_version(fh.path);  // versioned-libc filenames (no content read)
        fh.components.insert(fh.components.end(), std::make_move_iterator(fv.begin()),
                             std::make_move_iterator(fv.end()));
        auto kv = scan_kernel_version(fm.span(), fh.path);  // Linux kernel banner (any file)
        fh.components.insert(fh.components.end(), std::make_move_iterator(kv.begin()),
                             std::make_move_iterator(kv.end()));
        auto ub = scan_uboot_version(fm.span(), fh.path);  // U-Boot banner (any file)
        fh.components.insert(fh.components.end(), std::make_move_iterator(ub.begin()),
                             std::make_move_iterator(ub.end()));
        if (auto cfg = extract_kconfig(fm.span())) {  // embedded kernel .config (IKCONFIG)
            fh.notable.push_back(kconfig_finding(*cfg));
            fh.has_kconfig = true;
            infer_from_kconfig_text(*cfg, fh.kcv);
            fh.kconfig_text = *cfg;
            fh.kconfig_source = "ikconfig";
        }
    }

    // Kernel-config inference (feeds the curated kernel-CVE checklist). Runs for
    // the SBOM or CVE passes. Sources beyond IKCONFIG (handled above): an on-disk
    // .config, /lib/modules manifests and .ko files, and — for a kernel image —
    // the decoded kallsyms table plus distinctive strings.
    if (passes.sbom || passes.cve) {
        std::string_view p = fh.path;
        auto ends = [&](std::string_view s) {
            return p.size() >= s.size() && p.compare(p.size() - s.size(), s.size(), s) == 0;
        };
        if (!fh.has_kconfig && looks_like_kconfig(fm.span())) {
            std::string cfg(reinterpret_cast<const char*>(fm.span().data()), fm.span().size());
            infer_from_kconfig_text(cfg, fh.kcv);
            fh.has_kconfig = true;
            fh.kconfig_text = std::move(cfg);
            fh.kconfig_source = "on-disk .config";
        }
        if (ends("modules.builtin"))
            infer_from_modules_builtin(fm.span(), fh.kcv);
        if (ends(".ko") || ends(".ko.gz") || ends(".ko.xz"))
            infer_from_ko_path(fh.path, fh.kcv);
        // A kernel image carries a "Linux version" banner. Decode its kallsyms
        // and scan its strings. Bounded to keep tree scans fast.
        if (fm.size() < (64u << 20)) {
            auto kv = scan_kernel_version(fm.span(), fh.path);
            if (!kv.empty()) {
                if (auto ks = decode_kallsyms(fm.span())) infer_from_kallsyms(*ks, fh.kcv);
                infer_from_kernel_strings(fm.span(), fh.kcv);
            }
        }
    }
    if (passes.licenses) fh.licenses = scan_licenses(fh.path, fm.span());

    // Detect the distro/release from os-release (for CVE release precision).
    if (passes.cve && fm.size() < (1u << 16)) {
        std::string_view p = fh.path;
        auto ends = [&](std::string_view s) {
            return p.size() >= s.size() && p.compare(p.size() - s.size(), s.size(), s) == 0;
        };
        if (ends("etc/os-release") || ends("usr/lib/os-release") || p == "os-release")
            parse_os_release(fm.span(), fh.distro_id, fh.distro_version);
    }
    return fh;
}

}  // namespace

Report scan_path(const std::string& root, const Passes& passes, unsigned nthreads,
                 const std::vector<ContentRule>& extra_content,
                 const std::vector<PathRule>& extra_paths) {
    Report rep;
    rep.root = root;

    // Build the engine once (shared, read-only, across workers) when the secrets
    // pass is active or the user supplied extra rules. Secrets, the notable-file
    // rules, and user rules ride the same engine.
    std::optional<Engine> engine;
    if (passes.secrets || !extra_content.empty() || !extra_paths.empty()) {
        std::vector<ContentRule> content = builtin_content_rules();
        std::vector<PathRule> paths = builtin_path_rules();
        content.insert(content.end(), extra_content.begin(), extra_content.end());
        paths.insert(paths.end(), extra_paths.begin(), extra_paths.end());
        engine.emplace(std::move(content), std::move(paths));
    }
    const Engine* eng = engine ? &*engine : nullptr;

    std::error_code ec;
    std::vector<fs::path> paths;
    std::vector<Component> sym_components;  // libc versions read off symlink targets
    fs::path root_path(root);
    fs::path rel_root;

    if (fs::is_directory(root_path, ec)) {
        rep.is_dir = true;
        rel_root = root_path;
        for (auto it = fs::recursive_directory_iterator(
                 root_path, fs::directory_options::skip_permission_denied, ec);
             !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (it->is_symlink()) {
                it.disable_recursion_pending();
                // A libc symlink (libc.so.0 -> libuClibc-0.9.30.so) carries the
                // version in its target name even when the target file was not
                // extracted. Read the link (no follow) and version off the target.
                if (passes.sbom) {
                    std::error_code sec;
                    fs::path tgt = fs::read_symlink(it->path(), sec);
                    if (!sec) {
                        auto fv = scan_filename_version(tgt.string());
                        if (!fv.empty()) {
                            std::error_code rc2;
                            std::string rel = fs::relative(it->path(), rel_root, rc2).string();
                            for (auto& c : fv) {
                                if (!rel.empty()) c.origin_path = rel;
                                sym_components.push_back(std::move(c));
                            }
                        }
                    }
                }
                continue;
            }
            std::error_code fec;
            if (it->is_regular_file(fec)) paths.push_back(it->path());
        }
        std::sort(paths.begin(), paths.end());
    } else {
        rep.is_dir = false;
        rel_root = root_path.has_parent_path() ? root_path.parent_path() : fs::path(".");
        paths.push_back(root_path);
    }

    const size_t n = paths.size();
    rep.file_count = n;

    std::vector<FileHits> results(n);
    if (nthreads == 0) nthreads = 1;
    nthreads = std::min<unsigned>(nthreads, std::max<size_t>(1, n));

    std::atomic<size_t> next{0};
    auto worker = [&] {
        for (size_t i = next.fetch_add(1); i < n; i = next.fetch_add(1))
            results[i] = scan_one(paths[i], rel_root, passes, eng);
    };
    std::vector<std::thread> pool;
    for (unsigned t = 0; t < nthreads; ++t) pool.emplace_back(worker);
    for (auto& th : pool) th.join();

    std::unordered_set<std::string> seen_components;
    for (auto& fh : results) {
        rep.bytes_scanned += fh.size;
        if (!fh.ok) {
            rep.errors.emplace_back(fh.path, fh.error);
            continue;
        }
        for (auto& f : fh.secrets) rep.secrets.push_back({fh.path, std::move(f)});
        for (auto& f : fh.notable) rep.notable.push_back({fh.path, std::move(f)});
        // Dedup components by identity (name, version, purl) — the same library
        // is found in many files and sometimes by two methods (a versioned
        // filename and a content banner give the same glibc). Keep the first
        // (path-sorted, deterministic). purl keeps distinct provenance apart
        // (pkg:deb/openssl vs pkg:generic/openssl are different components).
        for (auto& c : fh.components) {
            if (c.name == "linux_kernel" && rep.kernel_version.empty()) rep.kernel_version = c.version;
            std::string k = c.name + "\x1f" + c.version + "\x1f" + c.purl;
            if (seen_components.insert(std::move(k)).second) rep.components.push_back(std::move(c));
        }
        for (auto& f : fh.licenses) rep.licenses.push_back({fh.path, std::move(f)});
        if (rep.distro_id.empty() && !fh.distro_id.empty()) {
            rep.distro_id = std::move(fh.distro_id);
            rep.distro_version = std::move(fh.distro_version);
        }
        if (fh.has_kconfig) rep.has_kconfig = true;
        // Keep the first (or largest) verbatim config recovered, preferring one.
        if (!fh.kconfig_text.empty() && fh.kconfig_text.size() > rep.kconfig_text.size()) {
            rep.kconfig_text = std::move(fh.kconfig_text);
            rep.kconfig_source = std::move(fh.kconfig_source);
        }
        merge_view(rep.kcv, fh.kcv);
    }
    // Symlink-target libc components, through the same dedup.
    for (auto& c : sym_components) {
        std::string k = c.name + "\x1f" + c.version + "\x1f" + c.purl;
        if (seen_components.insert(std::move(k)).second) rep.components.push_back(std::move(c));
    }
    return rep;
}

}  // namespace ft
