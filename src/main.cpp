// main.cpp — mithril CLI entry point.
//
// mithril is the semantic/content-analysis sibling to moria: it reasons about
// what is *in* the software (secrets, SBOM, CVEs, licenses) over a file or an
// unpacked firmware tree (typically moria's `-e` output). Phase 1 implements the
// secrets pass; SBOM / CVE / licenses are stubbed until their phases land.
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>

#include <unistd.h>

#include "cve.hpp"
#include "osvindex.hpp"
#include "cveupdate.hpp"
#include "dbpath.hpp"
#include "kernelcve.hpp"
#include "human.hpp"
#include "json.hpp"
#include "report.hpp"
#include "sbom_emit.hpp"
#include "userrules.hpp"

#ifndef MITHRIL_VERSION
#define MITHRIL_VERSION "dev"
#endif

namespace {

const char* basename_of(const char* p) {
    const char* b = p;
    for (const char* s = p; *s; ++s)
        if (*s == '/') b = s + 1;
    return b;
}

void print_help(std::FILE* out, const char* prog, bool color) {
    const char* B = color ? "\033[1m" : "";
    const char* R = color ? "\033[0m" : "";
    std::fprintf(out, "Analyze software contents: secrets, components (SBOM), CVEs, licenses.\n\n");
    std::fprintf(out, "%sUSAGE%s\n", B, R);
    std::fprintf(out, "  %s [options] <file|dir>\n\n", prog);
    std::fprintf(out, "%sOPTIONS%s\n", B, R);
    std::fprintf(out,
                 "  -j, --json          JSON output (default: human-readable)\n"
                 "      --secrets       Scan file content for credential/key material\n"
                 "      --sbom          Inventory software components and versions\n"
                 "      --cve           Match components against known vulnerabilities\n"
                 "      --licenses      Identify open-source licenses\n"
                 "  -A, --all           Run every pass (the default when none is selected)\n"
                 "      --rules <FILE>  Add user-defined rules from a JSON file\n"
                 "      --fetch-db      Download a prebuilt CVE mirror, then exit\n"
                 "      --update-db     Rebuild the local CVE mirror from source, then exit\n"
                 "  -C, --outdir <DIR>  Write the JSON report to DIR/mithril-report.json\n"
                 "      --dump-kconfig  Print the recovered kernel .config to stdout, then exit\n"
                 "      --threads <N>   Worker threads for tree scans (default: auto)\n"
                 "  -h, --help          Print help\n"
                 "      --version       Print version\n\n");
    std::fprintf(out, "%sEXAMPLES%s\n", B, R);
    std::fprintf(out,
                 "  %s ./rootfs/            Run every analysis on an unpacked tree\n"
                 "  %s --secrets ./rootfs/  Only the secrets pass\n"
                 "  %s -j ./rootfs/         JSON for tools / LLMs\n\n",
                 prog, prog, prog);
    std::fprintf(out, "Pipeline: moria -e firmware.bin  ->  mithril firmware.bin.extracted/\n");
    std::fprintf(out, "Docs: README.md, docs/\n");
}


}  // namespace

int main(int argc, char** argv) {
    using namespace ft;
    const auto t_start = std::chrono::steady_clock::now();
    const char* prog = basename_of(argv[0]);

    std::string path, outdir_cli, rules_cli;
    unsigned threads = 0;  // 0 -> auto
    bool json_out = false;
    bool update_db = false;
    bool fetch_db = false;
    bool dump_kconfig = false;
    Passes passes;
    bool have_path = false;
    bool end_of_opts = false;

    if (argc == 1) {
        bool color = isatty(fileno(stdout)) && !std::getenv("NO_COLOR");
        print_help(stdout, prog, color);
        return 0;
    }

    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (!end_of_opts && std::strcmp(a, "--") == 0) {
            end_of_opts = true;
        } else if (!end_of_opts && (std::strcmp(a, "-h") == 0 || std::strcmp(a, "--help") == 0)) {
            bool color = isatty(fileno(stdout)) && !std::getenv("NO_COLOR");
            print_help(stdout, prog, color);
            return 0;
        } else if (!end_of_opts && std::strcmp(a, "--version") == 0) {
            std::printf("%s %s\n", prog, MITHRIL_VERSION);
            return 0;
        } else if (!end_of_opts && (std::strcmp(a, "-j") == 0 || std::strcmp(a, "--json") == 0)) {
            json_out = true;
        } else if (!end_of_opts && std::strcmp(a, "--secrets") == 0) {
            passes.secrets = true;
        } else if (!end_of_opts && std::strcmp(a, "--sbom") == 0) {
            passes.sbom = true;
        } else if (!end_of_opts && std::strcmp(a, "--cve") == 0) {
            passes.cve = true;
        } else if (!end_of_opts && std::strcmp(a, "--licenses") == 0) {
            passes.licenses = true;
        } else if (!end_of_opts && (std::strcmp(a, "-A") == 0 || std::strcmp(a, "--all") == 0)) {
            passes.all();
        } else if (!end_of_opts && (std::strcmp(a, "-C") == 0 || std::strcmp(a, "--outdir") == 0) &&
                   i + 1 < argc) {
            outdir_cli = argv[++i];
        } else if (!end_of_opts && std::strcmp(a, "--update-db") == 0) {
            update_db = true;
        } else if (!end_of_opts && std::strcmp(a, "--fetch-db") == 0) {
            fetch_db = true;
        } else if (!end_of_opts && std::strcmp(a, "--dump-kconfig") == 0) {
            dump_kconfig = true;
        } else if (!end_of_opts && std::strcmp(a, "--rules") == 0 && i + 1 < argc) {
            rules_cli = argv[++i];
        } else if (!end_of_opts && std::strcmp(a, "--threads") == 0 && i + 1 < argc) {
            threads = static_cast<unsigned>(std::strtoul(argv[++i], nullptr, 10));
        } else if (!end_of_opts && a[0] == '-' && a[1] != '\0') {
            std::fprintf(stderr, "%s: unknown option '%s'\nTry '%s --help'.\n", prog, a, prog);
            return 2;
        } else if (!have_path) {
            path = a;
            have_path = true;
        } else {
            std::fprintf(stderr, "%s: unexpected argument '%s'\nTry '%s --help'.\n", prog, a, prog);
            return 2;
        }
    }

    // --fetch-db / --update-db are standalone actions (the only networked paths);
    // no scan target. --fetch-db downloads a prebuilt index; --update-db rebuilds
    // it from source. If both are given, the authoritative rebuild wins.
    if (update_db || fetch_db) {
        std::string err;
        const char* action = update_db ? "--update-db" : "--fetch-db";
        int rc = update_db ? cve_update(err) : cve_fetch(err);
        if (rc != 0) {
            std::fprintf(stderr, "%s: %s: %s\n", prog, action, err.c_str());
            return 1;
        }
        return 0;
    }

    if (!have_path) {
        std::fprintf(stderr, "%s: missing <file|dir>\nTry '%s --help'.\n", prog, prog);
        return 2;
    }
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        std::fprintf(stderr, "%s: no such file or directory: %s\n", prog, path.c_str());
        return 1;
    }

    // No pass selected -> run them all (like a bare `mithril <tree>`).
    if (!passes.any()) passes.all();

    if (threads == 0) {
        threads = std::thread::hardware_concurrency();
        if (threads == 0) threads = 1;
    }

    // All four passes are implemented. The CVE join needs an SBOM to join
    // against, so --cve implies the SBOM pass.
    Passes impl = passes;
    if (impl.cve) impl.sbom = true;
    // --dump-kconfig only needs the config extraction that rides the SBOM pass;
    // run just that, print the recovered .config, and exit before the report.
    if (dump_kconfig) { impl = Passes{}; impl.sbom = true; }

    // Load user-defined rules, if any. A load error is fatal (a typo in a rule
    // file should not silently scan with fewer rules than the operator thinks).
    UserRules user;
    if (!rules_cli.empty()) {
        user = load_user_rules(rules_cli);
        if (!user.ok()) {
            std::fprintf(stderr, "%s: --rules: %s\n", prog, user.error.c_str());
            return 1;
        }
        // User content/path rules ride the secrets pass's engine; make sure it runs.
        if (!user.content.empty() || !user.paths.empty()) impl.secrets = true;
    }

    Report rep = scan_path(path, impl, threads, user.content, user.paths);

    // --dump-kconfig: emit the verbatim recovered .config (IKCONFIG or on-disk)
    // and exit. Nonzero when none was found so scripts can tell.
    if (dump_kconfig) {
        if (rep.kconfig_text.empty()) {
            std::fprintf(stderr, "%s: no kernel .config recovered from %s\n", prog, path.c_str());
            return 1;
        }
        std::fwrite(rep.kconfig_text.data(), 1, rep.kconfig_text.size(), stdout);
        if (rep.kconfig_text.back() != '\n') std::fputc('\n', stdout);
        return 0;
    }

    // CVE join (downstream of the SBOM): match components against the local
    // mirror. OSV covers package-DB components (dpkg/apk); the NVD augment covers
    // the CPE-bearing binary-version components.
    bool cve_db_missing = false;
    if (impl.cve) {
        OsvIndex osv;
        bool have_osv = osv.open(osv_index_path());
        auto nvd = load_nvd_db(nvd_index_path());
        if (!have_osv && !nvd) {
            // The CVE pass cannot run without the local mirror. Make this loud: a
            // scan-level entry in errors[] (empty path == not file-scoped) and a
            // nonzero exit, so a script or agent never mistakes "DB absent" for
            // "target is clean". Point at --fetch-db (the prebuilt mirror);
            // --update-db is the power-user rebuild.
            cve_db_missing = true;
            std::string msg =
                std::string("cve: no local vuln DB; run '") + prog + " --fetch-db' first";
            rep.errors.emplace_back(std::string(), msg);
            std::fprintf(stderr, "%s: %s\n", prog, msg.c_str());
        } else {
            // Release precision applies where the image's VERSION_ID aligns with
            // the OSV release tag: Debian ("11") and Ubuntu ("20.04"). rpm distros
            // are left agnostic (VERSION_ID "8.5" vs OSV rel "8" would mis-match).
            std::string release = (rep.distro_id == "debian" || rep.distro_id == "ubuntu")
                                      ? rep.distro_version
                                      : std::string();
            if (have_osv) rep.cves = cve_join(osv, rep.components, rep.distro_id, release);
            if (nvd) {
                auto nm = nvd_join(*nvd, rep.components);
                rep.cves.insert(rep.cves.end(), nm.begin(), nm.end());
            }
            // Reconcile across sources: dedup (cve, component), keep richest CVSS.
            rep.cves = reconcile_cves(std::move(rep.cves));
        }
        // Curated kernel-CVE checklist, gated by version + kconfig (independent of
        // the OSV/NVD mirror — the table is built in).
        rep.kernel_cves = kernel_cve_scan(rep.kernel_version, &rep.kcv);

        // Value-add annotation only (never affects applicability): tag findings
        // that are on CISA KEV or carry an EPSS score.
        auto kev = load_kev(kev_index_path());
        auto epss = load_epss(epss_index_path());
        if (!kev.empty() || !epss.empty()) {
            auto ann_kev = [&](const std::string& id) { return kev.count(id) > 0; };
            auto ann_epss = [&](const std::string& id) {
                auto it = epss.find(id);
                return it == epss.end() ? -1.0 : it->second;
            };
            for (auto& m : rep.cves) {
                m.kev = ann_kev(m.cve_id);
                m.epss = ann_epss(m.cve_id);
            }
            for (auto& k : rep.kernel_cves) {
                k.kev = ann_kev(k.cve);
                k.epss = ann_epss(k.cve);
            }
        }
    }

    const double secs =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();

    // Optional: write the JSON report (and, for SBOM, the standard-format SBOMs)
    // to files regardless of stdout mode.
    if (!outdir_cli.empty()) {
        std::filesystem::create_directories(outdir_cli, ec);
        auto write_file = [&](const std::string& name, const std::string& content) {
            std::string fp = outdir_cli + "/" + name;
            if (std::FILE* rf = std::fopen(fp.c_str(), "wb")) {
                std::fwrite(content.data(), 1, content.size(), rf);
                std::fputc('\n', rf);
                std::fclose(rf);
                std::fprintf(stderr, "wrote %s\n", fp.c_str());
            } else {
                std::fprintf(stderr, "%s: cannot write %s\n", prog, fp.c_str());
            }
        };
        write_file("mithril-report.json", emit_report_json(rep, impl));
        if (impl.sbom) {
            write_file("sbom.cdx.json", emit_cyclonedx(rep.components, MITHRIL_VERSION));
            write_file("sbom.spdx.json", emit_spdx(rep.components, MITHRIL_VERSION));
        }
    }

    if (json_out) {
        std::string j = emit_report_json(rep, impl);
        std::fwrite(j.data(), 1, j.size(), stdout);
        std::fputc('\n', stdout);
    } else {
        char foot[128];
        std::snprintf(foot, sizeof(foot), "Scanned %zu file%s (%zu bytes) in %.3f s",
                      rep.file_count, rep.file_count == 1 ? "" : "s", rep.bytes_scanned, secs);
        bool color = isatty(fileno(stdout)) && !std::getenv("NO_COLOR");
        std::string h = emit_report_human(rep, impl, foot, color);
        std::fwrite(h.data(), 1, h.size(), stdout);
    }

    // A requested CVE pass with no local mirror is a real failure, not a clean
    // scan: exit nonzero so callers notice even when parsing only the exit code.
    return cve_db_missing ? 1 : 0;
}
