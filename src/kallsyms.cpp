#include "kallsyms.hpp"

#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>

#define KSDBG(...) do { if (std::getenv("KSDBG")) std::fprintf(stderr, __VA_ARGS__); } while (0)

namespace ft {

namespace {

// A symbol name character (after the leading type byte). The kernel's symbol
// namespace is C identifiers plus a few link-time decorations.
bool ident_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '_' || c == '.' || c == '$';
}

// Read an unsigned little-endian word (4 or 8 bytes) at off.
uint64_t rdword(std::span<const uint8_t> d, size_t off, unsigned wsz) {
    uint64_t v = 0;
    for (unsigned i = 0; i < wsz; ++i) v |= uint64_t(d[off + i]) << (8 * i);
    return v;
}

uint16_t rd16(std::span<const uint8_t> d, size_t off) {
    return uint16_t(d[off] | (uint16_t(d[off + 1]) << 8));
}

// Located token machinery: the 256 token strings and their index offsets.
struct TokenTables {
    size_t table_start = 0;   // byte offset of kallsyms_token_table
    size_t index_start = 0;   // byte offset of kallsyms_token_index (right after table)
    uint16_t index[256] = {};
};

// Verify a candidate kallsyms_token_index at `ti`: 256 little-endian uint16, the
// first 0 and each strictly greater than the last by a small token length. When
// it validates, recover token_table start by finding the table length K such
// that every token_index[i] lands on a token boundary (the byte before it is a
// NUL terminator) and the last token ends exactly at ti-1.
bool try_token_tables(std::span<const uint8_t> d, size_t ti, TokenTables& out) {
    if (ti + 512 > d.size()) return false;
    uint16_t idx[256];
    uint16_t prev = 0;
    for (int i = 0; i < 256; ++i) {
        uint16_t v = rd16(d, ti + size_t(i) * 2);
        if (i == 0) {
            if (v != 0) return false;
        } else {
            // strictly increasing; each token is >=1 byte incl its NUL, and real
            // tokens are short. Anything wilder is not a token index.
            if (v <= prev || v - prev > 64) return false;
        }
        idx[i] = v;
        prev = v;
    }
    // token_table = 256 NUL-terminated strings, ending right before ti. Its
    // length K satisfies: K > index[255] (last token starts inside the table),
    // d[ti-1]==0 (last terminator), and for each i>=1 the byte just before
    // token i (table_start+index[i]) is the previous token's NUL terminator.
    if (d[ti - 1] != 0x00) return false;
    size_t table_start = 0;
    for (size_t K = size_t(idx[255]) + 2; K <= size_t(idx[255]) + 66 && K <= ti; ++K) {
        size_t ts = ti - K;
        bool ok = true;
        for (int i = 1; i < 256 && ok; ++i)
            if (d[ts + idx[i] - 1] != 0x00) ok = false;  // terminator of token i-1
        // token 0 starts at ts and must be non-empty printable-ish (not a NUL).
        if (ok && d[ts] == 0x00) ok = false;
        if (ok) { table_start = ts; break; }
    }
    if (!table_start) return false;
    size_t tbl_len = ti - table_start;
    for (int i = 0; i < 256; ++i)
        if (idx[i] >= tbl_len) return false;
    out.table_start = table_start;
    out.index_start = ti;
    for (int i = 0; i < 256; ++i) out.index[i] = idx[i];
    return true;
}

// Decode one symbol at names[pos]; append its bare name (type char dropped) to
// `out`. Returns the next position, or 0 on malformed input.
size_t decode_symbol(std::span<const uint8_t> d, const TokenTables& tt, size_t tbl_len,
                     size_t pos, std::string& out) {
    if (pos >= d.size()) return 0;
    size_t len = d[pos++];
    // "big kallsyms" (>=5.x): high bit set means a second length byte follows.
    if (len & 0x80) {
        if (pos >= d.size()) return 0;
        len = (len & 0x7f) | (size_t(d[pos++]) << 7);
    }
    // No real symbol has this many tokens; also bounds work at bogus offsets.
    if (len == 0 || len > 256 || pos + len > d.size()) return 0;
    std::string sym;
    for (size_t k = 0; k < len; ++k) {
        uint8_t tokidx = d[pos + k];
        size_t toff = tt.table_start + tt.index[tokidx];
        // token is NUL-terminated within the table
        while (toff < tt.table_start + tbl_len && d[toff] != 0x00) {
            sym.push_back(char(d[toff]));
            ++toff;
        }
    }
    pos += len;
    if (sym.empty()) return 0;
    // sym[0] is the type char (t/T/d/r/b/A/W/...); the remainder is the name.
    std::string name = sym.substr(1);
    if (name.empty()) return 0;
    for (unsigned char c : name)
        if (!ident_char(c)) return 0;
    out = std::move(name);
    return pos;
}

struct Markers {
    size_t names_end = 0;  // offset of markers[0] (== end of kallsyms_names)
    uint64_t m1 = 0;       // markers[1]: byte length of the first 256 symbols
    size_t count = 0;      // number of markers == ceil(num_syms/256)
};

// Find kallsyms_markers (== end of kallsyms_names). markers is an array of
// `unsigned long` offsets-into-names, values increasing from 0, sitting just
// before token_table (after a little alignment padding).
Markers find_markers(std::span<const uint8_t> d, size_t table_start, unsigned wsz) {
    Markers out;
    if (table_start < 64) return out;
    size_t lo = (table_start > (16u << 20)) ? table_start - (16u << 20) : 0;
    for (size_t ms = table_start - wsz; ms >= lo + wsz; ms -= wsz) {
        if (((table_start - ms) % wsz) != 0) continue;
        if (rdword(d, ms, wsz) != 0) continue;  // markers[0] == 0
        size_t q = ms;
        uint64_t prev = 0;
        size_t count = 0;
        bool first = true;
        while (q + wsz <= table_start) {
            uint64_t v = rdword(d, q, wsz);
            if (first) { first = false; }  // v==0 already checked
            else {
                if (v <= prev) break;
                if (v > (64u << 20)) break;
            }
            prev = v;
            ++count;
            q += wsz;
        }
        if (count >= 2 && (table_start - q) < 2 * wsz) {  // reaches token_table
            out.names_end = ms;
            out.m1 = rdword(d, ms + wsz, wsz);  // markers[1]
            out.count = count;
            return out;
        }
    }
    return out;
}

// Locate kallsyms_names via the address/offset array that precedes it.
// kallsyms_addresses (absolute kernels) or kallsyms_offsets (BASE_RELATIVE
// kernels) is a run of num_syms monotonically non-decreasing words, followed —
// within a few words (relative_base and/or padding) — by kallsyms_num_syms,
// whose value equals the run length, then kallsyms_names. The value==length
// coincidence is a decisive anchor. Returns candidate (names_start, num_syms)
// pairs to a callback until it accepts one; used so the caller can validate by
// actually decoding. Returns names_start of the accepted candidate, or 0.
template <typename Accept>
size_t find_symtab_anchor(std::span<const uint8_t> d, size_t table_start, unsigned wsz,
                          uint64_t& num_syms_out, Accept accept) {
    // Only consider high-bit words (kernel addresses: MIPS 0x80.., ARM 0xc0..,
    // arm64 0xffff..). This is the absolute-kallsyms case; BASE_RELATIVE kernels
    // have no such array and are handled by the markers path below. Restricting
    // to high-bit runs keeps this to at most a couple of candidate runs.
    const uint64_t hibit = uint64_t(1) << (wsz * 8 - 1);
    size_t hi = table_start;
    size_t run_start = 0;
    uint64_t prev = 0;
    bool inrun = false;
    for (size_t p = 0; p + wsz <= hi; p += wsz) {
        uint64_t v = rdword(d, p, wsz);
        bool addr = (v & hibit) != 0;
        if (addr && (!inrun || v >= prev)) {
            if (!inrun) { inrun = true; run_start = p; }
            prev = v;
            continue;
        }
        // Monotonic address run ended at p. num_syms (== run length) sits within
        // a few words after the array; find it, skip zero padding to the first
        // kallsyms_names length byte, and let the caller validate by decoding.
        if (inrun) {
            size_t run_len = (p - run_start) / wsz;
            if (run_len >= 2000 && run_len <= 500000) {
                for (size_t q = p; q + wsz <= hi && q <= p + 8 * wsz; q += wsz) {
                    if (rdword(d, q, wsz) != run_len) continue;
                    size_t ns = q + wsz;
                    while (ns < hi && d[ns] == 0x00 && ns < q + wsz + 32) ++ns;
                    if (ns < hi && d[ns] != 0x00 && accept(ns, run_len)) {
                        num_syms_out = run_len;
                        return ns;
                    }
                    break;
                }
            }
        }
        inrun = addr;
        if (addr) { run_start = p; prev = v; }
    }
    return 0;
}

// Decode the names blob. Layout: ... num_syms, names, markers, token_table.
// names_end is markers[0] (found above). num_syms is the word right before
// names_start. Scan word-aligned candidates below names_end for a count `w`
// such that decoding exactly `w` symbols lands exactly on names_end; a wrong
// candidate overshoots or fails fast, so this stays cheap.
bool decode_names(std::span<const uint8_t> d, const TokenTables& tt, unsigned wsz, Kallsyms& ks) {
    size_t tbl_len = tt.index_start - tt.table_start;

    // Fast path: address/offset-array anchor. Decodes num_syms names from the
    // candidate start and accepts only if core symbols appear.
    {
        uint64_t ns = 0;
        Kallsyms cand;
        auto accept = [&](size_t names_start, uint64_t nsyms) -> bool {
            Kallsyms c;
            c.names.reserve(nsyms);
            size_t pos = names_start;
            for (uint64_t i = 0; i < nsyms; ++i) {
                std::string name;
                size_t np = decode_symbol(d, tt, tbl_len, pos, name);
                if (np == 0 || np > tt.table_start) return false;
                c.names.insert(std::move(name));
                pos = np;
            }
            if (!c.names.count("commit_creds") && !c.names.count("prepare_kernel_cred") &&
                !c.names.count("do_exit") && !c.names.count("kmalloc"))
                return false;
            cand = std::move(c);
            return true;
        };
        size_t names_start = find_symtab_anchor(d, tt.table_start, wsz, ns, accept);
        if (names_start) {
            cand.complete = true;
            KSDBG("[ks] anchor names_start=0x%zx num_syms=%llu syms=%zu\n", names_start,
                  (unsigned long long)ns, cand.names.size());
            ks = std::move(cand);
            return true;
        }
    }

    Markers mk = find_markers(d, tt.table_start, wsz);
    KSDBG("[ks] wsz=%u table_start=0x%zx names_end=0x%zx m1=%llu M=%zu\n", wsz, tt.table_start,
          mk.names_end, (unsigned long long)mk.m1, mk.count);
    if (!mk.names_end || mk.m1 < 64) return false;
    size_t names_end = mk.names_end;
    // Up to this many bytes of alignment padding between names and markers[0].
    const size_t kPad = 2 * wsz;
    size_t win_lo = (names_end > (8u << 20)) ? names_end - (8u << 20) : 0;
    if (win_lo < wsz) win_lo = wsz;
    // Scan for the true names_start: a boundary whose preceding word
    // (kallsyms_num_syms) is plausible and whose first 256 symbols span exactly
    // markers[1] bytes. That O(256) gate makes the full decode run at most once.
    size_t mlo = (mk.count >= 2) ? (mk.count - 2) * 256 : 0;
    size_t mhi = (mk.count + 1) * 256;
    for (size_t s = names_end - wsz; s >= win_lo; s -= wsz) {
        // Cheap prefilter: s must be a valid symbol boundary (decode 1 symbol).
        std::string nm0;
        size_t np0 = decode_symbol(d, tt, tbl_len, s, nm0);
        if (np0 == 0 || np0 > names_end) continue;
        uint64_t numsyms = rdword(d, s - wsz, wsz);
        if (numsyms < 500 || numsyms > 500000) continue;  // plausible num_syms
        if (numsyms <= mlo || numsyms > mhi) continue;     // ~ M*256
        // Gate: decode exactly 256 symbols; their byte span must equal markers[1].
        size_t pos = s;
        bool g = true;
        for (int i = 0; i < 256; ++i) {
            std::string nm;
            size_t np = decode_symbol(d, tt, tbl_len, pos, nm);
            if (np == 0 || np > names_end) { g = false; break; }
            pos = np;
        }
        if (!g || (pos - s) != mk.m1) continue;
        // Full decode from s, counting symbols until the blob is consumed.
        pos = s;
        size_t c = 0;
        bool ok = true;
        while (pos < names_end) {
            if (names_end - pos <= kPad && rdword(d, pos, wsz) == 0) break;  // hit padding/markers
            std::string nm;
            size_t np = decode_symbol(d, tt, tbl_len, pos, nm);
            if (np == 0 || np > names_end) { ok = false; break; }
            pos = np;
            if (++c > numsyms) { ok = false; break; }
        }
        if (!ok || c != numsyms || names_end - pos > kPad) continue;
        // Geometry holds; decode again collecting names.
        Kallsyms cand;
        cand.names.reserve(c);
        pos = s;
        for (size_t i = 0; i < c; ++i) {
            std::string name;
            size_t np = decode_symbol(d, tt, tbl_len, pos, name);
            if (np == 0) break;
            cand.names.insert(std::move(name));
            pos = np;
        }
        if (!cand.names.count("commit_creds") && !cand.names.count("prepare_kernel_cred") &&
            !cand.names.count("do_exit") && !cand.names.count("kmalloc"))
            continue;
        cand.complete = true;
        KSDBG("[ks] names_start=0x%zx num_syms=%llu syms=%zu\n", s, (unsigned long long)numsyms,
              cand.names.size());
        ks = std::move(cand);
        return true;
    }
    KSDBG("[ks] no names_start (names_end=0x%zx)\n", names_end);
    return false;
}

}  // namespace

std::optional<Kallsyms> decode_kallsyms(std::span<const uint8_t> data) {
    if (data.size() < 4096) return std::nullopt;
    // Scan for the token_index anchor: 256 increasing uint16 starting at 0.
    // Cheap prefilter: a run beginning with two zero bytes then a small value.
    for (size_t i = 0; i + 512 <= data.size(); i += 2) {
        if (data[i] != 0 || data[i + 1] != 0) continue;      // index[0] == 0
        if (data[i + 2] == 0 && data[i + 3] == 0) continue;  // index[1] > 0
        TokenTables tt;
        if (!try_token_tables(data, i, tt)) continue;
        for (unsigned wsz : {4u, 8u}) {
            Kallsyms ks;
            if (decode_names(data, tt, wsz, ks)) return ks;
        }
    }
    return std::nullopt;
}

}  // namespace ft
