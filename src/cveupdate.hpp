// cveupdate.hpp — build/refresh the local OSV mirror (the `--update-db` action).
//
// The only networked path in mithril, and only when the operator asks. Downloads
// the OSV per-ecosystem archives (Debian, Alpine — matching the dpkg/apk SBOM
// sources), unzips them, and normalizes the OSV records into the compact index
// that the CVE join reads offline (cve.hpp). Delegates the fetch/unzip to the
// `curl` and `unzip` binaries at arm's length; parses the records in-process.
#pragma once

#include <string>

namespace ft {

// Fetch + normalize both mirrors (OSV + NVD) into the data dir. Returns 0 on
// success; on failure returns non-zero and sets `err`. Progress to stderr.
// This is the authoritative rebuild path (scrapes OSV + NVD at the source).
// `with_kernel_feed` additionally builds the full kernel.org CVE feed (a large
// extra download; off by default — it only serves --kernel-cves-all).
int cve_update(std::string& err, bool with_kernel_feed = false);

// Download a prebuilt index from the rolling release (or $MITHRIL_DB_URL) and
// install it into the data dir, verifying every asset against a served
// SHA256SUMS. The fast path for a client that does not want to scrape OSV/NVD.
// Returns 0 on success; on failure returns non-zero and sets `err`.
// `with_kernel_feed` also fetches the optional kernel-cve-index.json asset.
int cve_fetch(std::string& err, bool with_kernel_feed = false);

// The two sources, independently (cve_update runs both).
int osv_update(std::string& err);  // OSV Debian+Alpine -> osv-index.json
int nvd_update(std::string& err);  // NVD per curated CPE product -> nvd-index.json
int kev_update(std::string& err);  // CISA KEV ids -> kev.json (annotation only)
int epss_update(std::string& err); // EPSS scores -> epss.txt (annotation only)
int kernel_feed_update(std::string& err);  // kernel.org vulns -> kernel-cve-index.json

}  // namespace ft
