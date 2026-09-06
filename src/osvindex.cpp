#include "osvindex.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <numeric>
#include <unordered_map>

namespace ft {

namespace {
namespace fs = std::filesystem;

constexpr uint32_t kHeaderSize = 64;
constexpr uint32_t kVersion = 1;
const char kMagic[4] = {'M', 'O', 'S', '1'};

void put8(std::string& b, uint8_t v) { b.push_back(static_cast<char>(v)); }
void put16(std::string& b, uint16_t v) { b.append(reinterpret_cast<const char*>(&v), 2); }
void put32(std::string& b, uint32_t v) { b.append(reinterpret_cast<const char*>(&v), 4); }

uint16_t rd16(const uint8_t* p) {
    uint16_t v;
    std::memcpy(&v, p, 2);
    return v;
}
uint32_t rd32(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}
uint64_t rd64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}

// The lookup key: "<eco>\x1f<pkg>". 0x1f sorts below any printable byte, so the
// byte order of these keys matches an (eco, pkg) tuple order — but the reader
// and writer both order by the composed key, so it is self-consistent regardless.
std::string compose_key(const std::string& eco, const std::string& pkg) {
    return eco + '\x1f' + pkg;
}

// Interns strings into a de-duplicated pool of {len u32, bytes} records; returns
// the byte offset (relative to the pool start) of a string.
struct StringPool {
    std::string bytes;
    std::unordered_map<std::string, uint32_t> seen;
    uint32_t intern(const std::string& s) {
        auto it = seen.find(s);
        if (it != seen.end()) return it->second;
        uint32_t off = static_cast<uint32_t>(bytes.size());
        put32(bytes, static_cast<uint32_t>(s.size()));
        bytes.append(s);
        seen.emplace(s, off);
        return off;
    }
};

}  // namespace

bool write_osv_index(const std::string& path, std::vector<OsvIndexEntry>& entries,
                     uint64_t generated_epoch, const std::string& source, std::string& err) {
    const size_t n = entries.size();

    // Order rows by composed key (stable, so a key's rows keep feed order).
    std::vector<std::string> keys(n);
    for (size_t i = 0; i < n; ++i) keys[i] = compose_key(entries[i].eco, entries[i].pkg);
    std::vector<uint32_t> ord(n);
    std::iota(ord.begin(), ord.end(), 0u);
    std::stable_sort(ord.begin(), ord.end(),
                     [&](uint32_t a, uint32_t b) { return keys[a] < keys[b]; });

    StringPool pool;
    std::string kd;    // key directory
    std::string recs;  // records blob
    uint32_t key_count = 0;

    for (size_t i = 0; i < n;) {
        const std::string& key = keys[ord[i]];
        uint32_t key_off = pool.intern(key);
        uint32_t rec_off = static_cast<uint32_t>(recs.size());
        uint32_t rec_count = 0;
        for (; i < n && keys[ord[i]] == key; ++i) {
            const OsvIndexEntry& e = entries[ord[i]];
            put32(recs, pool.intern(e.id));
            put32(recs, pool.intern(e.sev));
            put32(recs, pool.intern(e.rel));
            put32(recs, pool.intern(e.sum));
            put16(recs, static_cast<uint16_t>(e.events.size()));
            for (const OsvEvent& ev : e.events) {
                put8(recs, static_cast<uint8_t>(ev.type));
                put32(recs, pool.intern(ev.value));
            }
            ++rec_count;
        }
        put32(kd, key_off);
        put32(kd, rec_off);
        put32(kd, rec_count);
        ++key_count;
    }

    uint32_t source_off = pool.intern(source);

    const uint32_t keydir_off = kHeaderSize;
    const uint32_t records_off = keydir_off + static_cast<uint32_t>(kd.size());
    const uint32_t strpool_off = records_off + static_cast<uint32_t>(recs.size());

    std::string hdr(kHeaderSize, '\0');
    std::memcpy(hdr.data(), kMagic, 4);
    auto set32 = [&](size_t off, uint32_t v) { std::memcpy(hdr.data() + off, &v, 4); };
    auto set64 = [&](size_t off, uint64_t v) { std::memcpy(hdr.data() + off, &v, 8); };
    set32(4, kVersion);
    set64(8, generated_epoch);
    set32(16, static_cast<uint32_t>(n));
    set32(20, key_count);
    set32(24, keydir_off);
    set32(28, records_off);
    set32(32, strpool_off);
    set32(36, source_off);

    const std::string tmp = path + ".tmp";
    std::FILE* f = std::fopen(tmp.c_str(), "wb");
    if (!f) {
        err = "cannot open for write: " + tmp;
        return false;
    }
    bool ok = std::fwrite(hdr.data(), 1, hdr.size(), f) == hdr.size() &&
              std::fwrite(kd.data(), 1, kd.size(), f) == kd.size() &&
              std::fwrite(recs.data(), 1, recs.size(), f) == recs.size() &&
              std::fwrite(pool.bytes.data(), 1, pool.bytes.size(), f) == pool.bytes.size();
    if (std::fclose(f) != 0) ok = false;
    if (!ok) {
        err = "write failed: " + tmp;
        std::error_code ec;
        fs::remove(tmp, ec);
        return false;
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        err = "rename failed: " + tmp + " -> " + path;
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

bool OsvIndex::open(const std::string& path) {
    if (!map_.open(path)) {
        error_ = map_.error();
        return false;
    }
    auto sp = map_.span();
    size_ = sp.size();
    if (size_ < kHeaderSize) {
        error_ = "index too short: " + path;
        return false;
    }
    base_ = sp.data();
    if (std::memcmp(base_, kMagic, 4) != 0) {
        error_ = "not a mithril OSV index: " + path;
        return false;
    }
    if (rd32(base_ + 4) != kVersion) {
        error_ = "unsupported index version: " + path;
        return false;
    }
    generated_ = rd64(base_ + 8);
    vuln_count_ = rd32(base_ + 16);
    key_count_ = rd32(base_ + 20);
    keydir_off_ = rd32(base_ + 24);
    records_off_ = rd32(base_ + 28);
    strpool_off_ = rd32(base_ + 32);
    source_off_ = rd32(base_ + 36);
    // Section offsets must sit inside the file, and the key directory must fit.
    if (keydir_off_ > size_ || records_off_ > size_ || strpool_off_ > size_ ||
        static_cast<uint64_t>(keydir_off_) + static_cast<uint64_t>(key_count_) * 12 > records_off_) {
        error_ = "corrupt index header: " + path;
        base_ = nullptr;
        return false;
    }
    return true;
}

std::string_view OsvIndex::str_at(uint32_t rel) const {
    uint64_t at = static_cast<uint64_t>(strpool_off_) + rel;
    if (at + 4 > size_) return {};
    uint32_t len = rd32(base_ + at);
    if (at + 4 + len > size_) return {};
    return std::string_view(reinterpret_cast<const char*>(base_ + at + 4), len);
}

std::vector<OsvVuln> OsvIndex::lookup(const std::string& eco, const std::string& pkg) const {
    std::vector<OsvVuln> out;
    if (!base_ || key_count_ == 0) return out;
    const std::string key = compose_key(eco, pkg);
    const std::string_view want(key);

    uint32_t lo = 0, hi = key_count_, found = key_count_;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const uint8_t* e = base_ + keydir_off_ + static_cast<uint64_t>(mid) * 12;
        std::string_view k = str_at(rd32(e));
        if (k == want) {
            found = mid;
            break;
        }
        if (k < want) lo = mid + 1;
        else hi = mid;
    }
    if (found == key_count_) return out;

    const uint8_t* e = base_ + keydir_off_ + static_cast<uint64_t>(found) * 12;
    uint32_t rec_off = rd32(e + 4);
    uint32_t rec_count = rd32(e + 8);
    const uint8_t* r = base_ + records_off_ + rec_off;
    const uint8_t* end = base_ + size_;
    out.reserve(rec_count);
    for (uint32_t j = 0; j < rec_count; ++j) {
        if (r + 18 > end) break;  // truncated/corrupt: stop
        OsvVuln ov;
        ov.id = std::string(str_at(rd32(r)));
        ov.severity = std::string(str_at(rd32(r + 4)));
        ov.release = std::string(str_at(rd32(r + 8)));
        ov.summary = std::string(str_at(rd32(r + 12)));
        uint16_t nev = rd16(r + 16);
        const uint8_t* ep = r + 18;
        ov.events.reserve(nev);
        for (uint16_t k = 0; k < nev; ++k) {
            if (ep + 5 > end) break;
            char type = static_cast<char>(ep[0]);
            ov.events.push_back({type, std::string(str_at(rd32(ep + 1)))});
            ep += 5;
        }
        r = ep;
        out.push_back(std::move(ov));
    }
    return out;
}

std::string OsvIndex::source() const {
    return base_ ? std::string(str_at(source_off_)) : std::string();
}

}  // namespace ft
