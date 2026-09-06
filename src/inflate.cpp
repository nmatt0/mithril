#include "inflate.hpp"

#include <array>

namespace ft {

namespace {

constexpr int MAXBITS = 15;

// LSB-first bit reader over the input span. Overrun is a hard error.
struct BitReader {
    std::span<const uint8_t> in;
    size_t byte = 0;
    int bitbuf = 0;
    int bitcnt = 0;
    bool bad = false;

    int bit() {
        if (bitcnt == 0) {
            if (byte >= in.size()) { bad = true; return 0; }
            bitbuf = in[byte++];
            bitcnt = 8;
        }
        int b = bitbuf & 1;
        bitbuf >>= 1;
        --bitcnt;
        return b;
    }
    // Read n bits, LSB first.
    int bits(int n) {
        int v = 0;
        for (int i = 0; i < n; ++i) v |= bit() << i;
        return v;
    }
    void align() { bitcnt = 0; }  // discard to byte boundary
};

// Canonical Huffman table (puff-style): count[len] and symbols sorted by (len,val).
struct Huff {
    std::array<int16_t, MAXBITS + 1> count{};
    std::vector<int16_t> symbol;
};

bool construct(Huff& h, const std::vector<int>& lengths) {
    h.count.fill(0);
    for (int L : lengths) {
        if (L < 0 || L > MAXBITS) return false;
        h.count[L]++;
    }
    h.count[0] = 0;
    // over-subscribed / incomplete check
    int left = 1;
    for (int len = 1; len <= MAXBITS; ++len) {
        left <<= 1;
        left -= h.count[len];
        if (left < 0) return false;  // over-subscribed
    }
    std::array<int, MAXBITS + 1> offs{};
    offs[1] = 0;
    for (int len = 1; len < MAXBITS; ++len) offs[len + 1] = offs[len] + h.count[len];
    h.symbol.assign(lengths.size(), 0);
    for (size_t sym = 0; sym < lengths.size(); ++sym)
        if (lengths[sym] != 0) h.symbol[offs[lengths[sym]]++] = static_cast<int16_t>(sym);
    return true;
}

int decode(BitReader& br, const Huff& h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= MAXBITS; ++len) {
        code |= br.bit();
        if (br.bad) return -1;
        int cnt = h.count[len];
        if (code - cnt < first) return h.symbol[index + (code - first)];
        index += cnt;
        first += cnt;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

const int kLenBase[29] = {3,  4,  5,  6,  7,  8,  9,  10,  11,  13,  15,  17,  19,  23, 27,
                          31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
const int kLenExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                           2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
const int kDistBase[30] = {1,    2,    3,    4,    5,    7,     9,     13,    17,   25,
                           33,   49,   65,   97,   129,  193,   257,   385,   513,  769,
                           1025, 1537, 2049, 3073, 4097, 6145,  8193,  12289, 16385, 24577};
const int kDistExtra[30] = {0, 0, 0,  0,  1,  1,  2,  2,  3,  3,  4,  4,  5,  5,  6,
                            6, 7, 7,  8,  8,  9,  9,  10, 10, 11, 11, 12, 12, 13, 13};

bool inflate_block(BitReader& br, const Huff& lh, const Huff& dh, std::vector<uint8_t>& out,
                   size_t max_out) {
    for (;;) {
        int sym = decode(br, lh);
        if (sym < 0) return false;
        if (sym == 256) return true;  // end of block
        if (sym < 256) {
            if (out.size() >= max_out) return false;
            out.push_back(static_cast<uint8_t>(sym));
        } else {
            sym -= 257;
            if (sym >= 29) return false;
            int len = kLenBase[sym] + br.bits(kLenExtra[sym]);
            int dsym = decode(br, dh);
            if (dsym < 0 || dsym >= 30) return false;
            size_t dist = kDistBase[dsym] + br.bits(kDistExtra[dsym]);
            if (br.bad || dist > out.size()) return false;
            if (out.size() + len > max_out) return false;
            size_t from = out.size() - dist;
            for (int i = 0; i < len; ++i) out.push_back(out[from + i]);
        }
    }
}

const Huff& fixed_lit() {
    static const Huff h = [] {
        std::vector<int> l(288);
        for (int i = 0; i < 144; ++i) l[i] = 8;
        for (int i = 144; i < 256; ++i) l[i] = 9;
        for (int i = 256; i < 280; ++i) l[i] = 7;
        for (int i = 280; i < 288; ++i) l[i] = 8;
        Huff hh;
        construct(hh, l);
        return hh;
    }();
    return h;
}
const Huff& fixed_dist() {
    static const Huff h = [] {
        std::vector<int> l(30, 5);
        Huff hh;
        construct(hh, l);
        return hh;
    }();
    return h;
}

bool dynamic_tables(BitReader& br, Huff& lh, Huff& dh) {
    static const int ord[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
    int hlit = br.bits(5) + 257;
    int hdist = br.bits(5) + 1;
    int hclen = br.bits(4) + 4;
    if (hlit > 286 || hdist > 30) return false;
    std::vector<int> cl(19, 0);
    for (int i = 0; i < hclen; ++i) cl[ord[i]] = br.bits(3);
    if (br.bad) return false;
    Huff clh;
    if (!construct(clh, cl)) return false;

    std::vector<int> lengths;
    lengths.reserve(hlit + hdist);
    while (static_cast<int>(lengths.size()) < hlit + hdist) {
        int sym = decode(br, clh);
        if (sym < 0) return false;
        if (sym < 16) {
            lengths.push_back(sym);
        } else if (sym == 16) {
            if (lengths.empty()) return false;
            int rep = 3 + br.bits(2);
            int prev = lengths.back();
            while (rep-- && static_cast<int>(lengths.size()) < hlit + hdist) lengths.push_back(prev);
        } else if (sym == 17) {
            int rep = 3 + br.bits(3);
            while (rep-- && static_cast<int>(lengths.size()) < hlit + hdist) lengths.push_back(0);
        } else {  // 18
            int rep = 11 + br.bits(7);
            while (rep-- && static_cast<int>(lengths.size()) < hlit + hdist) lengths.push_back(0);
        }
        if (br.bad) return false;
    }
    std::vector<int> ll(lengths.begin(), lengths.begin() + hlit);
    std::vector<int> dl(lengths.begin() + hlit, lengths.end());
    if (!construct(lh, ll)) return false;
    // A single zero-length distance table is valid (no back-references).
    if (!construct(dh, dl)) return false;
    return true;
}

}  // namespace

std::optional<std::vector<uint8_t>> inflate_raw(std::span<const uint8_t> in, size_t max_out) {
    BitReader br{in};
    std::vector<uint8_t> out;
    for (;;) {
        int final_ = br.bit();
        int type = br.bits(2);
        if (br.bad) return std::nullopt;
        if (type == 0) {  // stored
            br.align();
            if (br.byte + 4 > in.size()) return std::nullopt;
            int len = in[br.byte] | (in[br.byte + 1] << 8);
            int nlen = in[br.byte + 2] | (in[br.byte + 3] << 8);
            br.byte += 4;
            if ((len ^ 0xFFFF) != nlen) return std::nullopt;
            if (br.byte + len > in.size()) return std::nullopt;
            if (out.size() + len > max_out) return std::nullopt;
            out.insert(out.end(), in.begin() + br.byte, in.begin() + br.byte + len);
            br.byte += len;
        } else if (type == 1) {
            if (!inflate_block(br, fixed_lit(), fixed_dist(), out, max_out)) return std::nullopt;
        } else if (type == 2) {
            Huff lh, dh;
            if (!dynamic_tables(br, lh, dh)) return std::nullopt;
            if (!inflate_block(br, lh, dh, out, max_out)) return std::nullopt;
        } else {
            return std::nullopt;  // reserved
        }
        if (final_) break;
    }
    return out;
}

std::optional<std::vector<uint8_t>> gzip_inflate(std::span<const uint8_t> in, size_t max_out) {
    if (in.size() < 10 || in[0] != 0x1f || in[1] != 0x8b || in[2] != 8) return std::nullopt;
    uint8_t flg = in[3];
    size_t p = 10;
    if (flg & 0x04) {  // FEXTRA
        if (p + 2 > in.size()) return std::nullopt;
        size_t xlen = in[p] | (in[p + 1] << 8);
        p += 2 + xlen;
    }
    if (flg & 0x08)  // FNAME
        while (p < in.size() && in[p++]) {}
    if (flg & 0x10)  // FCOMMENT
        while (p < in.size() && in[p++]) {}
    if (flg & 0x02) p += 2;  // FHCRC
    if (p > in.size()) return std::nullopt;
    return inflate_raw(in.subspan(p), max_out);
}

}  // namespace ft
