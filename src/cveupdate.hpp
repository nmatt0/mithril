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
int cve_update(std::string& err);

// The two sources, independently (cve_update runs both).
int osv_update(std::string& err);  // OSV Debian+Alpine -> osv-index.json
int nvd_update(std::string& err);  // NVD per curated CPE product -> nvd-index.json
int kev_update(std::string& err);  // CISA KEV ids -> kev.json (annotation only)
int epss_update(std::string& err); // EPSS scores -> epss.txt (annotation only)

}  // namespace ft
