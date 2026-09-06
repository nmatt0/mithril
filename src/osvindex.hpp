// osvindex.hpp — the compact, memory-mapped OSV index (see docs/cve-index-format.md).
//
// The OSV mirror is millions of rows but the CVE join only does point lookups by
// (ecosystem, package) for the handful of components in an SBOM. The old JSON
// index forced a full parse + heap load of every row on each scan (~1.15 GB /
// ~7 s). This binary format is mmap'd (load is O(1), near-zero RAM) with a sorted
// key directory + a de-duplicated string pool, so a lookup binary-searches the
// keys and materializes only the matched key's vulns.
//
// Layout (little-endian; a lookup reads via memcpy so unaligned access is safe):
//   Header   64 bytes: magic "MOS1", version, generated epoch, vuln/key counts,
//            section offsets, source string offset.
//   KeyDir   key_count x {key_off, rec_off, rec_count} (u32), sorted by key bytes.
//   Records  per vuln {id_off, sev_off, rel_off, sum_off (u32), nevents (u16),
//            nevents x (type u8, ver_off u32)}; a key's vulns are contiguous.
//   StrPool  de-duplicated {len u32, bytes} strings; every *_off is relative here.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "cve.hpp"  // OsvEvent, OsvVuln
#include "file_map.hpp"

namespace ft {

// One normalized OSV row to serialize: a single affected-range for one (eco,pkg).
struct OsvIndexEntry {
    std::string eco, pkg, id, sev, rel, sum;
    std::vector<OsvEvent> events;
};

// Write the compact binary OSV index to `path` (atomic: tmp file + rename). Sorts
// `entries` by key, pools and de-duplicates strings, groups vulns per (eco,pkg).
bool write_osv_index(const std::string& path, std::vector<OsvIndexEntry>& entries,
                     uint64_t generated_epoch, const std::string& source, std::string& err);

// A memory-mapped, read-only OSV index. `open` is O(1) (mmap + header validate);
// `lookup` binary-searches the key directory and materializes only the matched
// key's vulns. Non-copyable/non-movable (holds the mmap) — use as a local.
class OsvIndex {
public:
    OsvIndex() = default;
    OsvIndex(const OsvIndex&) = delete;
    OsvIndex& operator=(const OsvIndex&) = delete;

    // Returns false if the file is missing, too short, or not a valid index
    // (message in error()).
    bool open(const std::string& path);
    const std::string& error() const { return error_; }

    // Vulns for (eco, pkg); empty if the key is absent. Materialized (owning
    // std::string), which is cheap because only a handful of keys are queried.
    std::vector<OsvVuln> lookup(const std::string& eco, const std::string& pkg) const;

    uint64_t generated() const { return generated_; }
    std::string source() const;
    uint32_t vuln_count() const { return vuln_count_; }

private:
    std::string_view str_at(uint32_t rel) const;  // pooled string at `rel`, or ""

    FileMap map_;
    const uint8_t* base_ = nullptr;
    size_t size_ = 0;
    uint32_t key_count_ = 0, keydir_off_ = 0, records_off_ = 0, strpool_off_ = 0, source_off_ = 0;
    uint32_t vuln_count_ = 0;
    uint64_t generated_ = 0;
    std::string error_;
};

}  // namespace ft
