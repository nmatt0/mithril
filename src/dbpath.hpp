// dbpath.hpp — where mithril's local vulnerability mirror lives.
//
// A regenerable data cache, not config, so it lives under the XDG data dir.
// Resolution order: $MITHRIL_DB (explicit override) > $XDG_DATA_HOME/mithril >
// ~/.local/share/mithril.
// The scan reads this offline; only `--update-db` writes it (over the network).
#pragma once

#include <string>

namespace ft {

// Absolute path to the mithril data directory (created on demand by callers).
std::string mithril_data_dir();

// The normalized OSV index file inside the data dir.
std::string osv_index_path();

// The normalized NVD (CPE) index file inside the data dir.
std::string nvd_index_path();

// Exploit-annotation data (value-add, never gates): CISA KEV ids and EPSS scores.
std::string kev_index_path();
std::string epss_index_path();

// The full kernel.org (Linux CNA) CVE feed index, consulted only by
// --kernel-cves-all. An optional asset: fetched/built out-of-band, absent by
// default so the base mirror stays lean.
std::string kernel_feed_path();

}  // namespace ft
