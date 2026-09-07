#include "cveupdate.hpp"

#include <cctype>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

#include "binver.hpp"
#include "cve.hpp"
#include "dbpath.hpp"
#include "filever.hpp"
#include "inflate.hpp"
#include "io_util.hpp"
#include "jsonparse.hpp"
#include "osvindex.hpp"
#include "sha256.hpp"
#include "strutil.hpp"

namespace ft {

namespace fs = std::filesystem;

namespace {

// The OSV ecosystems we mirror. Debian/Ubuntu/Alpine serve the dpkg/apk package
// DBs (Ubuntu picked over Debian when the image's os-release id is ubuntu); the
// language ecosystems serve langmanifest components; the rpm distros serve
// rpm-database components (mapped by the image's /etc/os-release id).
const std::vector<std::string> kEcosystems = {
    "Debian",     "Ubuntu",   "Alpine",      "npm",         "PyPI",      "Go",
    "crates.io",  "Packagist", "RubyGems",   "Red Hat",     "Rocky Linux", "AlmaLinux",
    "openSUSE",   "SUSE"};
constexpr const char* kBaseUrl = "https://osv-vulnerabilities.storage.googleapis.com/";

// URL-encode spaces (the only special char in our ecosystem names, e.g. "Red Hat").
std::string url_encode(const std::string& s) {
    std::string o;
    for (char c : s) o += (c == ' ') ? std::string("%20") : std::string(1, c);
    return o;
}
// Filesystem-safe name for temp files (spaces/dots -> '_').
std::string fs_safe(const std::string& s) {
    std::string o;
    for (char c : s) o += (c == ' ' || c == '.') ? '_' : c;
    return o;
}

// Run argv (no shell, so no injection); inherit stdio. Returns exit status, or
// 127 if the program could not be exec'd.
int run_argv(const std::vector<std::string>& args) {
    std::vector<char*> argv;
    for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        ::execvp(argv[0], argv.data());
        _exit(127);
    }
    int status = 0;
    ::waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

std::string base_eco(const std::string& full) {
    size_t colon = full.find(':');
    return colon == std::string::npos ? full : full.substr(0, colon);
}

// Normalized rows are OsvIndexEntry (osvindex.hpp); rel = release ("11" from
// "Debian:11"). Written to the compact binary index by write_osv_index.
using Entry = OsvIndexEntry;

// The release suffix of an OSV ecosystem string ("Debian:11" -> "11"; "" if none).
std::string eco_release(const std::string& full) {
    size_t colon = full.find(':');
    return colon == std::string::npos ? std::string() : full.substr(colon + 1);
}

// The numeric release token (\d+\.\d+) in a string, or "". Ubuntu OSV ecosystems
// carry the release in varied shapes -- "Ubuntu:22.04:LTS", "Ubuntu:Pro:18.04:LTS",
// "Ubuntu:Pro:FIPS:16.04:LTS" -- and we normalize to the bare "22.04" so it matches
// the image's os-release VERSION_ID.
std::string numeric_release(const std::string& s) {
    for (size_t i = 0; i < s.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(s[i]))) continue;
        size_t j = i;
        while (j < s.size() && std::isdigit(static_cast<unsigned char>(s[j]))) ++j;
        if (j < s.size() && s[j] == '.') {
            size_t k = j + 1;
            while (k < s.size() && std::isdigit(static_cast<unsigned char>(s[k]))) ++k;
            if (k > j + 1) return s.substr(i, k - i);
        }
        i = j;  // skip the digit run we just scanned
    }
    return {};
}

// Extract entries for `want_eco` from one OSV record.
void extract(const JsonValue& j, const std::string& want_eco, std::vector<Entry>& out) {
    std::string id = j.get_str("id");
    // Prefer a CVE alias as the reported id.
    if (const JsonValue* al = j.find("aliases"); al && al->is_array())
        for (const JsonValue& a : al->arr)
            if (a.is_string() && a.str.rfind("CVE-", 0) == 0) {
                id = a.str;
                break;
            }
    std::string summary = j.get_str("summary");
    if (summary.empty()) {
        summary = j.get_str("details");
        if (summary.size() > 160) summary = summary.substr(0, 157) + "...";
    }
    std::string sev;
    if (const JsonValue* s = j.find("severity"); s && s->is_array() && !s->arr.empty())
        sev = s->arr[0].get_str("score");

    const JsonValue* affected = j.find("affected");
    if (!affected || !affected->is_array()) return;
    for (const JsonValue& aff : affected->arr) {
        const JsonValue* pkg = aff.find("package");
        if (!pkg) continue;
        std::string full_eco = pkg->get_str("ecosystem");
        if (base_eco(full_eco) != want_eco) continue;
        std::string release = eco_release(full_eco);
        if (want_eco == "Ubuntu") {
            // Skip the FIPS tiers: their version scheme ("...fips...") is a
            // separate track that would mis-compare against a stock image, and
            // FIPS on an embedded device is rare. Stock LTS + Pro/ESM (which
            // carry old-release coverage the user needs) are kept, release
            // normalized to the bare "XX.YY".
            if (full_eco.find("FIPS") != std::string::npos) continue;
            release = numeric_release(full_eco);
        }
        std::string name = pkg->get_str("name");
        if (name.empty()) continue;

        const JsonValue* ranges = aff.find("ranges");
        if (!ranges || !ranges->is_array()) continue;
        for (const JsonValue& rng : ranges->arr) {
            const JsonValue* events = rng.find("events");
            if (!events || !events->is_array()) continue;
            Entry e;
            e.id = canonical_cve(id);
            e.eco = want_eco;
            e.rel = release;
            e.pkg = name;
            e.sev = sev;
            e.sum = summary;
            for (const JsonValue& ev : events->arr) {
                if (const JsonValue* v = ev.find("introduced")) e.events.push_back({'i', v->str});
                else if (const JsonValue* v2 = ev.find("fixed")) e.events.push_back({'f', v2->str});
                else if (const JsonValue* v3 = ev.find("last_affected"))
                    e.events.push_back({'l', v3->str});
            }
            if (!e.events.empty()) out.push_back(std::move(e));
        }
    }
}

}  // namespace

int osv_update(std::string& err) {
    const std::string data_dir = mithril_data_dir();
    std::error_code ec;
    fs::create_directories(data_dir, ec);
    if (ec) {
        err = "cannot create data dir: " + data_dir;
        return 1;
    }
    const std::string tmp = data_dir + "/osv-tmp";
    fs::remove_all(tmp, ec);
    fs::create_directories(tmp, ec);

    std::vector<Entry> entries;
    for (const auto& eco : kEcosystems) {
        std::string url = std::string(kBaseUrl) + url_encode(eco) + "/all.zip";
        std::string zip = tmp + "/" + fs_safe(eco) + ".zip";
        std::string dir = tmp + "/" + fs_safe(eco);
        fs::create_directories(dir, ec);

        std::fprintf(stderr, "fetching %s ...\n", url.c_str());
        int rc = run_argv({"curl", "-sSL", "--fail", "-o", zip, url});
        if (rc != 0) {
            err = "curl failed for " + eco + " (rc=" + std::to_string(rc) +
                  "; is curl installed / is the network reachable?)";
            return 1;
        }
        std::fprintf(stderr, "unzipping %s ...\n", eco.c_str());
        rc = run_argv({"unzip", "-oq", zip, "-d", dir});
        if (rc != 0) {
            err = "unzip failed for " + eco + " (rc=" + std::to_string(rc) + ")";
            return 1;
        }

        size_t before = entries.size();
        for (auto it = fs::recursive_directory_iterator(dir, ec);
             !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (!it->is_regular_file(ec)) continue;
            if (it->path().extension() != ".json") continue;
            auto j = json_parse(read_file(it->path().string()).value_or(std::string()));
            if (j && j->is_object()) extract(*j, eco, entries);
        }
        std::fprintf(stderr, "  %s: %zu affected-range entries\n", eco.c_str(),
                     entries.size() - before);
    }

    // Serialize the normalized index to the compact binary format (osvindex.hpp).
    std::string source = "osv.dev ";
    for (size_t i = 0; i < kEcosystems.size(); ++i) source += (i ? "," : "") + kEcosystems[i];

    const std::string index = osv_index_path();
    if (!write_osv_index(index, entries, static_cast<uint64_t>(std::time(nullptr)), source, err))
        return 1;
    fs::remove_all(tmp, ec);  // keep only the normalized index

    std::fprintf(stderr, "wrote %s (%zu entries)\n", index.c_str(), entries.size());
    return 0;
}

namespace {

// One normalized NVD cpeMatch entry.
struct NvdEntry {
    std::string id, vendor, product, cvss, ver, si, se, ei, ee;
};

// Pull a CVSS vector from the NVD "metrics" object (prefer v3.1 > v3.0 > v2).
std::string nvd_cvss(const JsonValue& cve) {
    const JsonValue* m = cve.find("metrics");
    if (!m) return {};
    for (const char* k : {"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"}) {
        const JsonValue* arr = m->find(k);
        if (arr && arr->is_array() && !arr->arr.empty()) {
            const JsonValue* d = arr->arr[0].find("cvssData");
            if (d) return d->get_str("vectorString");
        }
    }
    return {};
}

// Field 3/4/5 of a CPE 2.3 string.
void cpe_fields(const std::string& c, std::string& vendor, std::string& product,
                std::string& version) {
    std::vector<std::string> f;
    size_t start = 0;
    while (start <= c.size()) {
        size_t colon = c.find(':', start);
        f.push_back(c.substr(start, colon == std::string::npos ? std::string::npos : colon - start));
        if (colon == std::string::npos) break;
        start = colon + 1;
    }
    if (f.size() >= 6) {
        vendor = f[3];
        product = f[4];
        version = f[5];
    }
}

void extract_nvd(const JsonValue& cve, const std::string& want_vendor,
                 const std::string& want_product, std::vector<NvdEntry>& out) {
    std::string id = cve.get_str("id");
    std::string cvss = nvd_cvss(cve);
    const JsonValue* configs = cve.find("configurations");
    if (!configs || !configs->is_array()) return;
    for (const JsonValue& cfg : configs->arr) {
        const JsonValue* nodes = cfg.find("nodes");
        if (!nodes || !nodes->is_array()) continue;
        for (const JsonValue& node : nodes->arr) {
            const JsonValue* matches = node.find("cpeMatch");
            if (!matches || !matches->is_array()) continue;
            for (const JsonValue& cm : matches->arr) {
                if (!cm.get_bool("vulnerable")) continue;
                std::string vendor, product, version;
                cpe_fields(cm.get_str("criteria"), vendor, product, version);
                if (vendor != want_vendor || product != want_product) continue;
                NvdEntry e;
                e.id = id;
                e.vendor = vendor;
                e.product = product;
                e.cvss = cvss;
                e.si = cm.get_str("versionStartIncluding");
                e.se = cm.get_str("versionStartExcluding");
                e.ei = cm.get_str("versionEndIncluding");
                e.ee = cm.get_str("versionEndExcluding");
                // A pinned version (not '*'/'-') with no bounds is an exact match.
                if (version != "*" && version != "-" && e.si.empty() && e.se.empty() &&
                    e.ei.empty() && e.ee.empty())
                    e.ver = version;
                out.push_back(std::move(e));
            }
        }
    }
}

}  // namespace

int nvd_update(std::string& err) {
    const std::string data_dir = mithril_data_dir();
    std::error_code ec;
    fs::create_directories(data_dir, ec);
    const std::string tmp = data_dir + "/nvd-tmp";
    fs::remove_all(tmp, ec);
    fs::create_directories(tmp, ec);

    std::vector<NvdEntry> entries;
    // Every CPE (vendor, product) the tool can emit: binver banners + filename libc.
    auto products = binver_cpe_products();
    for (auto& p : filever_cpe_products()) {
        bool dup = false;
        for (auto& q : products)
            if (q == p) dup = true;
        if (!dup) products.push_back(p);
    }
    for (size_t i = 0; i < products.size(); ++i) {
        const auto& [vendor, product] = products[i];
        std::string vms = "virtualMatchString=cpe:2.3:a:" + vendor + ":" + product;
        std::string outfile = tmp + "/" + vendor + "_" + product + ".json";
        std::fprintf(stderr, "querying NVD for %s:%s ...\n", vendor.c_str(), product.c_str());
        int rc = run_argv({"curl", "-sS", "--fail", "--get",
                          "https://services.nvd.nist.gov/rest/json/cves/2.0", "--data-urlencode",
                          vms, "--data-urlencode", "resultsPerPage=2000", "-o", outfile});
        if (rc != 0) {
            err = "curl failed for NVD " + product + " (rc=" + std::to_string(rc) + ")";
            return 1;
        }
        auto doc = json_parse(read_file(outfile).value_or(std::string()));
        if (!doc || !doc->is_object()) {
            std::fprintf(stderr, "  warning: unparseable NVD response for %s\n", product.c_str());
        } else {
            long total = static_cast<long>(doc->get_num("totalResults"));
            if (total > 2000)
                std::fprintf(stderr, "  warning: %s has %ld CVEs (>2000); only the first page kept\n",
                             product.c_str(), total);
            const JsonValue* vulns = doc->find("vulnerabilities");
            size_t before = entries.size();
            if (vulns && vulns->is_array())
                for (const JsonValue& item : vulns->arr)
                    if (const JsonValue* c = item.find("cve"))
                        extract_nvd(*c, vendor, product, entries);
            std::fprintf(stderr, "  %s:%s: %zu cpeMatch entries\n", vendor.c_str(), product.c_str(),
                         entries.size() - before);
        }
        // NVD rate limit without an API key is 5 requests / 30s; be polite.
        if (i + 1 < products.size()) ::sleep(6);
    }

    std::string out = "{\"schema\":1,\"source\":\"nvd.nist.gov API 2.0\",\"generated\":\"";
    {
        std::time_t t = std::time(nullptr);
        std::tm tm{};
        gmtime_r(&t, &tm);
        char b[32];
        std::strftime(b, sizeof(b), "%Y-%m-%dT%H:%M:%SZ", &tm);
        out += b;
    }
    out += "\",\"vulns\":[";
    for (size_t i = 0; i < entries.size(); ++i) {
        const NvdEntry& e = entries[i];
        if (i) out += ",";
        out += "{\"id\":\"";
        json_escape(out, e.id);
        out += "\",\"vendor\":\"";
        json_escape(out, e.vendor);
        out += "\",\"product\":\"";
        json_escape(out, e.product);
        out += "\"";
        auto kv = [&](const char* k, const std::string& v) {
            if (!v.empty()) {
                out += ",\"";
                out += k;
                out += "\":\"";
                json_escape(out, v);
                out += "\"";
            }
        };
        kv("cvss", e.cvss);
        kv("ver", e.ver);
        kv("si", e.si);
        kv("se", e.se);
        kv("ei", e.ei);
        kv("ee", e.ee);
        out += "}";
    }
    out += "]}";

    const std::string index = nvd_index_path();
    std::FILE* f = std::fopen(index.c_str(), "wb");
    if (!f) {
        err = "cannot write index: " + index;
        return 1;
    }
    std::fwrite(out.data(), 1, out.size(), f);
    std::fclose(f);
    fs::remove_all(tmp, ec);
    std::fprintf(stderr, "wrote %s (%zu entries)\n", index.c_str(), entries.size());
    return 0;
}

int kev_update(std::string& err) {
    const std::string data_dir = mithril_data_dir();
    std::error_code ec;
    fs::create_directories(data_dir, ec);
    const std::string raw = data_dir + "/kev-raw.json";
    std::fprintf(stderr, "fetching CISA KEV ...\n");
    int rc = run_argv({"curl", "-sSL", "--fail", "-o", raw,
                      "https://www.cisa.gov/sites/default/files/feeds/"
                      "known_exploited_vulnerabilities.json"});
    if (rc != 0) {
        err = "curl failed for KEV (rc=" + std::to_string(rc) + ")";
        return 1;
    }
    auto doc = json_parse(read_file(raw).value_or(std::string()));
    fs::remove(raw, ec);
    if (!doc || !doc->is_object()) {
        err = "KEV feed unparseable";
        return 1;
    }
    std::string out = "{\"source\":\"cisa.gov KEV\",\"cves\":[";
    size_t n = 0;
    if (const JsonValue* v = doc->find("vulnerabilities"); v && v->is_array())
        for (const JsonValue& e : v->arr) {
            std::string id = e.get_str("cveID");
            if (id.rfind("CVE-", 0) != 0) continue;
            if (n++) out += ",";
            out += "\"";
            json_escape(out, id);
            out += "\"";
        }
    out += "]}";
    std::FILE* f = std::fopen(kev_index_path().c_str(), "wb");
    if (!f) {
        err = "cannot write " + kev_index_path();
        return 1;
    }
    std::fwrite(out.data(), 1, out.size(), f);
    std::fclose(f);
    std::fprintf(stderr, "wrote %s (%zu known-exploited CVEs)\n", kev_index_path().c_str(), n);
    return 0;
}

int epss_update(std::string& err) {
    const std::string data_dir = mithril_data_dir();
    std::error_code ec;
    fs::create_directories(data_dir, ec);
    const std::string gz = data_dir + "/epss.csv.gz";
    std::fprintf(stderr, "fetching EPSS ...\n");
    int rc = run_argv({"curl", "-sSL", "--fail", "-o", gz,
                      "https://epss.cyentia.com/epss_scores-current.csv.gz"});
    if (rc != 0) {
        err = "curl failed for EPSS (rc=" + std::to_string(rc) + ")";
        return 1;
    }
    std::string raw = read_file(gz).value_or(std::string());
    fs::remove(gz, ec);
    auto csv = gzip_inflate(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(raw.data()),
                                                     raw.size()),
                            256u << 20);
    if (!csv) {
        err = "EPSS gzip inflate failed";
        return 1;
    }
    // Rows are "CVE-YYYY-NNNN,<epss>,<percentile>"; skip # comments and the header.
    std::string out;
    std::string_view text(reinterpret_cast<const char*>(csv->data()), csv->size());
    size_t start = 0, n = 0;
    while (start < text.size()) {
        size_t nl = text.find('\n', start);
        std::string_view line(text.data() + start,
                              (nl == std::string_view::npos ? text.size() : nl) - start);
        start = (nl == std::string_view::npos) ? text.size() : nl + 1;
        if (line.rfind("CVE-", 0) != 0) continue;
        size_t c1 = line.find(',');
        if (c1 == std::string_view::npos) continue;
        size_t c2 = line.find(',', c1 + 1);
        std::string_view score = line.substr(c1 + 1, (c2 == std::string_view::npos ? line.size() : c2) - c1 - 1);
        out.append(line.substr(0, c1));
        out += ',';
        out.append(score);
        out += '\n';
        ++n;
    }
    std::FILE* f = std::fopen(epss_index_path().c_str(), "wb");
    if (!f) {
        err = "cannot write " + epss_index_path();
        return 1;
    }
    std::fwrite(out.data(), 1, out.size(), f);
    std::fclose(f);
    std::fprintf(stderr, "wrote %s (%zu EPSS scores)\n", epss_index_path().c_str(), n);
    return 0;
}

namespace {

// Default location of the prebuilt index (a rolling GitHub release updated by
// the update-db CI workflow). Overridable via $MITHRIL_DB_URL for a fork/mirror
// or an internal cache. No trailing slash.
std::string db_base_url() {
    if (const char* u = std::getenv("MITHRIL_DB_URL"); u && *u) {
        std::string s = u;
        if (!s.empty() && s.back() == '/') s.pop_back();
        return s;
    }
    return "https://github.com/nmatt0/mithril/releases/download/db-latest";
}

// One prebuilt asset: the served filename, the final path in the data dir, and
// whether the served file is gzip-compressed (inflated in-process on install).
struct Asset {
    std::string served;              // filename in the release + in SHA256SUMS
    std::string dest;                // final path in the data dir
    bool gz;                         // served as .gz -> inflate before install
};

// Parse a coreutils-style SHA256SUMS body ("<hex>  <name>" per line) into a
// name -> lowercase-hex map. The " *name" (binary) marker is tolerated.
std::map<std::string, std::string> parse_sha256sums(const std::string& body) {
    std::map<std::string, std::string> m;
    size_t start = 0;
    while (start < body.size()) {
        size_t nl = body.find('\n', start);
        std::string line = body.substr(start, (nl == std::string::npos ? body.size() : nl) - start);
        start = (nl == std::string::npos) ? body.size() : nl + 1;
        size_t sp = line.find(' ');
        if (sp != 64) continue;  // first token must be a 64-char hex digest
        std::string hash = line.substr(0, 64);
        size_t name_at = line.find_first_not_of(" *", sp);
        if (name_at == std::string::npos) continue;
        std::string name = line.substr(name_at);
        while (!name.empty() && (name.back() == '\r' || name.back() == ' ')) name.pop_back();
        for (char& c : hash) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        m[name] = hash;
    }
    return m;
}

}  // namespace

int cve_fetch(std::string& err) {
    const std::string data_dir = mithril_data_dir();
    std::error_code ec;
    fs::create_directories(data_dir, ec);
    if (ec) {
        err = "cannot create data dir: " + data_dir;
        return 1;
    }
    const std::string base = db_base_url();
    const std::string tmp = data_dir + "/fetch-tmp";
    fs::remove_all(tmp, ec);
    fs::create_directories(tmp, ec);

    // Integrity manifest first: every asset is verified against it before install.
    const std::string sums_path = tmp + "/SHA256SUMS";
    std::fprintf(stderr, "fetching SHA256SUMS from %s ...\n", base.c_str());
    if (run_argv({"curl", "-sSL", "--fail", "-o", sums_path, base + "/SHA256SUMS"}) != 0) {
        err = "curl failed for SHA256SUMS (is the network reachable? is the db-latest "
              "release published?)";
        fs::remove_all(tmp, ec);
        return 1;
    }
    auto sums = parse_sha256sums(read_file(sums_path).value_or(std::string()));
    if (sums.empty()) {
        err = "SHA256SUMS is empty or unparseable";
        fs::remove_all(tmp, ec);
        return 1;
    }

    const std::vector<Asset> assets = {
        {"osv-index.mdb.gz", osv_index_path(), true},
        {"nvd-index.json", nvd_index_path(), false},
        {"kev.json", kev_index_path(), false},
        {"epss.txt.gz", epss_index_path(), true},
    };

    for (const Asset& a : assets) {
        auto it = sums.find(a.served);
        if (it == sums.end()) {
            err = a.served + " is not listed in SHA256SUMS";
            fs::remove_all(tmp, ec);
            return 1;
        }
        const std::string dl = tmp + "/" + a.served;
        std::fprintf(stderr, "fetching %s ...\n", a.served.c_str());
        if (run_argv({"curl", "-sSL", "--fail", "-o", dl, base + "/" + a.served}) != 0) {
            err = "curl failed for " + a.served;
            fs::remove_all(tmp, ec);
            return 1;
        }
        std::string bytes = read_file(dl).value_or(std::string());
        std::string got = sha256_hex(bytes);
        if (got != it->second) {
            err = "checksum mismatch for " + a.served + " (expected " + it->second + ", got " +
                  got + ") -- download corrupt or tampered";
            fs::remove_all(tmp, ec);
            return 1;
        }

        // Install atomically: write final content to a temp path in the data dir
        // (same filesystem as the destination), then rename over the old file.
        const std::string staged = a.dest + ".new";
        std::string content;
        if (a.gz) {
            auto inflated = gzip_inflate(
                std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(bytes.data()),
                                         bytes.size()),
                1024u << 20);  // 1 GiB cap: the osv index can be a few hundred MB
            if (!inflated) {
                err = "gzip inflate failed for " + a.served;
                fs::remove_all(tmp, ec);
                return 1;
            }
            content.assign(reinterpret_cast<const char*>(inflated->data()), inflated->size());
        } else {
            content = std::move(bytes);
        }
        std::FILE* f = std::fopen(staged.c_str(), "wb");
        if (!f) {
            err = "cannot write " + staged;
            fs::remove_all(tmp, ec);
            return 1;
        }
        std::fwrite(content.data(), 1, content.size(), f);
        std::fclose(f);
        fs::rename(staged, a.dest, ec);
        if (ec) {
            err = "cannot install " + a.dest + ": " + ec.message();
            fs::remove_all(tmp, ec);
            return 1;
        }
        std::fprintf(stderr, "  installed %s (%zu bytes)\n", a.dest.c_str(), content.size());
    }

    fs::remove_all(tmp, ec);
    std::fprintf(stderr, "fetched prebuilt vulnerability index into %s\n", data_dir.c_str());
    return 0;
}

int cve_update(std::string& err) {
    if (int rc = osv_update(err)) return rc;
    if (int rc = nvd_update(err)) return rc;
    if (int rc = kev_update(err)) return rc;
    if (int rc = epss_update(err)) return rc;
    return 0;
}

}  // namespace ft
