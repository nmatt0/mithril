// derkey.cpp — raw DER private-key scanner. See derkey.hpp.
//
// ASN.1/DER shapes recognized (all reachable with no PEM wrapper):
//   PKCS#8  PrivateKeyInfo   SEQ { INTEGER 0, AlgId SEQ { OID [, params] }, OCTET STRING }
//   PKCS#1  RSAPrivateKey    SEQ { INTEGER 0, INTEGER n, INTEGER e, ... }   (9 INTEGERs)
//   SEC1    ECPrivateKey     SEQ { INTEGER 1, OCTET STRING d, [0] params, [1] pubkey }
//
// Strategy: Aho-Corasick over a few length-independent byte anchors that begin
// the SEQUENCE *content* (the version INTEGER), then for each hit recover the
// enclosing SEQUENCE header and run a full TLV parse. Every byte read goes
// through the bounds-checked Reader, so a hostile length just fails the parse.
#include "derkey.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "ahocorasick.hpp"

namespace ft {

namespace {

// ---- ASN.1 DER TLV --------------------------------------------------------

struct Tlv {
    uint8_t tag = 0;
    size_t body = 0;  // offset of the content
    size_t len = 0;   // content length
    size_t end = 0;   // body + len (offset just past this TLV)
};

std::optional<uint8_t> u8(const Reader& r, size_t off) { return r.at<uint8_t>(off, Endian::Big); }

// Parse a definite-length DER TLV at `off`. Rejects indefinite form and >4 length
// bytes (neither occurs in a DER private key). nullopt on any overrun.
std::optional<Tlv> tlv(const Reader& r, size_t off) {
    auto tag = u8(r, off);
    auto l0 = u8(r, off + 1);
    if (!tag || !l0) return std::nullopt;
    size_t hdr, len;
    if (*l0 < 0x80) {
        len = *l0;
        hdr = 2;
    } else {
        int nb = *l0 & 0x7f;
        if (nb == 0 || nb > 4) return std::nullopt;  // indefinite / absurd length
        len = 0;
        for (int i = 0; i < nb; ++i) {
            auto b = u8(r, off + 2 + static_cast<size_t>(i));
            if (!b) return std::nullopt;
            len = (len << 8) | *b;
        }
        hdr = 2 + static_cast<size_t>(nb);
    }
    const size_t body = off + hdr;
    const size_t end = body + len;
    if (end < body || end > r.size()) return std::nullopt;  // overflow / past EOF
    return Tlv{*tag, body, len, end};
}

bool oid_is(const Reader& r, const Tlv& t, std::span<const uint8_t> want) {
    if (t.tag != 0x06 || t.len != want.size()) return false;
    auto b = r.bytes(t.body, t.len);
    return b && std::equal(want.begin(), want.end(), b->begin());
}

// Known algorithm/curve OIDs (the bytes after `06 <len>`).
constexpr uint8_t OID_RSA[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
constexpr uint8_t OID_EC[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
constexpr uint8_t OID_ED25519[] = {0x2B, 0x65, 0x70};
constexpr uint8_t OID_ED448[] = {0x2B, 0x65, 0x71};
constexpr uint8_t OID_X25519[] = {0x2B, 0x65, 0x6E};
constexpr uint8_t OID_X448[] = {0x2B, 0x65, 0x6F};
constexpr uint8_t OID_P256[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
constexpr uint8_t OID_P384[] = {0x2B, 0x81, 0x04, 0x00, 0x22};
constexpr uint8_t OID_P521[] = {0x2B, 0x81, 0x04, 0x00, 0x23};
constexpr uint8_t OID_SECP256K1[] = {0x2B, 0x81, 0x04, 0x00, 0x0A};

std::string curve_from_oid(const Reader& r, const Tlv& oid) {
    if (oid_is(r, oid, OID_P256)) return "secp256r1";
    if (oid_is(r, oid, OID_P384)) return "secp384r1";
    if (oid_is(r, oid, OID_P521)) return "secp521r1";
    if (oid_is(r, oid, OID_SECP256K1)) return "secp256k1";
    return "";
}

std::string curve_from_scalar(size_t n) {
    switch (n) {
        case 32: return "P-256";
        case 48: return "secp384r1";
        case 66: return "secp521r1";
        default: return "";
    }
}

// Bit size of an INTEGER's value (drop a single DER sign-padding 0x00).
size_t int_bits(const Reader& r, const Tlv& i) {
    size_t len = i.len;
    auto first = u8(r, i.body);
    if (len > 1 && first && *first == 0x00) --len;
    return len * 8;
}

// ---- key classification ---------------------------------------------------

struct Key {
    size_t start = 0;  // offset of the outer SEQUENCE tag
    size_t end = 0;    // offset just past the key
    std::string label;
};

// PKCS#8: label from the AlgorithmIdentifier (+ modulus/curve peek). `after_alg`
// is the offset of the privateKey OCTET STRING that follows the AlgId.
std::string pkcs8_label(const Reader& r, const Tlv& algid, size_t after_alg) {
    auto oid = tlv(r, algid.body);
    if (!oid || oid->tag != 0x06) return "";

    if (oid_is(r, *oid, OID_RSA)) {
        // privateKey OCTET STRING -> RSAPrivateKey SEQ -> version, modulus.
        auto oct = tlv(r, after_alg);
        if (oct && oct->tag == 0x04) {
            auto inner = tlv(r, oct->body);
            if (inner && inner->tag == 0x30) {
                auto ver = tlv(r, inner->body);
                if (ver && ver->tag == 0x02) {
                    auto mod = tlv(r, ver->end);
                    if (mod && mod->tag == 0x02)
                        return "RSA-" + std::to_string(int_bits(r, *mod));
                }
            }
        }
        return "RSA";
    }
    if (oid_is(r, *oid, OID_EC)) {
        auto params = tlv(r, oid->end);  // named curve OID
        std::string c = (params && params->tag == 0x06) ? curve_from_oid(r, *params) : "";
        return c.empty() ? "EC" : ("EC " + c);
    }
    if (oid_is(r, *oid, OID_ED25519)) return "Ed25519";
    if (oid_is(r, *oid, OID_ED448)) return "Ed448";
    if (oid_is(r, *oid, OID_X25519)) return "X25519";
    if (oid_is(r, *oid, OID_X448)) return "X448";
    return "";  // unknown algorithm -> not a key we vouch for
}

// Given an outer SEQUENCE whose content is [cstart, cend), decide whether it is a
// private key and, if so, its label. Requires the children to consume the
// SEQUENCE exactly — the structural check that rejects coincidental byte runs.
std::optional<std::string> classify(const Reader& r, size_t cstart, size_t cend) {
    auto ver = tlv(r, cstart);
    if (!ver || ver->tag != 0x02 || ver->len != 1) return std::nullopt;
    auto vb = u8(r, ver->body);
    if (!vb) return std::nullopt;
    const uint8_t version = *vb;

    if (version == 0) {
        auto nxt = tlv(r, ver->end);
        if (!nxt) return std::nullopt;

        if (nxt->tag == 0x30) {  // PKCS#8: AlgorithmIdentifier SEQUENCE
            std::string label = pkcs8_label(r, *nxt, nxt->end);
            if (label.empty()) return std::nullopt;
            auto oct = tlv(r, nxt->end);  // privateKey OCTET STRING
            if (!oct || oct->tag != 0x04) return std::nullopt;
            if (oct->end > cend) return std::nullopt;  // must fit the SEQUENCE
            return label;
        }
        if (nxt->tag == 0x02) {  // PKCS#1 RSAPrivateKey: version + 8 INTEGERs
            size_t bits = int_bits(r, *nxt);
            size_t count = 2;  // version + modulus
            size_t p = nxt->end;
            while (p < cend) {
                auto c = tlv(r, p);
                if (!c || c->tag != 0x02) return std::nullopt;  // all fields are INTEGERs
                ++count;
                p = c->end;
            }
            if (p != cend || count != 9) return std::nullopt;
            if (bits < 512) return std::nullopt;  // implausible modulus
            return "RSA-" + std::to_string(bits);
        }
        return std::nullopt;
    }

    if (version == 1) {  // SEC1 ECPrivateKey
        auto oct = tlv(r, ver->end);
        if (!oct || oct->tag != 0x04) return std::nullopt;
        std::string curve = curve_from_scalar(oct->len);
        size_t p = oct->end;
        while (p < cend) {  // optional [0] params, [1] publicKey
            auto c = tlv(r, p);
            if (!c) return std::nullopt;
            if (c->tag == 0xA0) {  // parameters -> named curve OID
                auto oid = tlv(r, c->body);
                if (oid && oid->tag == 0x06) {
                    std::string cc = curve_from_oid(r, *oid);
                    if (!cc.empty()) curve = cc;
                }
            }
            p = c->end;
        }
        if (p != cend || curve.empty()) return std::nullopt;
        return "EC " + curve;
    }
    return std::nullopt;
}

// An anchor lands on the version INTEGER (first child of the outer SEQUENCE).
// Recover the enclosing SEQUENCE header, then classify.
std::optional<Key> parse_at_version(const Reader& r, size_t vpos) {
    for (size_t hdr = 2; hdr <= 6 && hdr <= vpos; ++hdr) {
        auto seq = tlv(r, vpos - hdr);
        if (!seq || seq->tag != 0x30 || seq->body != vpos) continue;
        if (auto label = classify(r, seq->body, seq->end))
            return Key{vpos - hdr, seq->end, *label};
    }
    return std::nullopt;
}

// Length-independent anchors that begin a private-key SEQUENCE's content.
const AhoCorasick& anchors() {
    static const AhoCorasick ac = [] {
        AhoCorasick a;
        const std::vector<std::vector<uint8_t>> pats = {
            {0x02, 0x01, 0x00, 0x30},        // PKCS#8 (version 0, AlgId SEQUENCE)
            {0x02, 0x01, 0x00, 0x02, 0x82},  // PKCS#1 RSA, modulus 256..65535 B (>=2048-bit)
            {0x02, 0x01, 0x00, 0x02, 0x81},  // PKCS#1 RSA, modulus 128..255 B  (~1024-bit)
            {0x02, 0x01, 0x01, 0x04, 0x20},  // SEC1 EC, 32-byte scalar (P-256/secp256k1)
            {0x02, 0x01, 0x01, 0x04, 0x30},  // SEC1 EC, 48-byte scalar (P-384)
            {0x02, 0x01, 0x01, 0x04, 0x42},  // SEC1 EC, 66-byte scalar (P-521)
        };
        for (uint32_t i = 0; i < pats.size(); ++i) a.add(pats[i], i);
        a.build();
        return a;
    }();
    return ac;
}

}  // namespace

std::vector<Finding> scan_der_private_keys(const Reader& r) {
    if (r.size() < 8) return {};

    std::vector<Key> hits;
    anchors().find(r.data(), 0, [&](size_t pos, uint32_t) -> bool {
        if (auto k = parse_at_version(r, pos)) hits.push_back(*k);
        return true;
    });
    if (hits.empty()) return {};

    // Dedup by overlap: keep the outermost key in any region so a PKCS#8 wrapper
    // and the PKCS#1 key nested in its OCTET STRING count once. Distinct keys at
    // distinct offsets (incl. redundant copies of one key) are all kept.
    std::sort(hits.begin(), hits.end(), [](const Key& a, const Key& b) {
        return a.start != b.start ? a.start < b.start : a.end > b.end;
    });

    std::vector<Finding> out;
    size_t claimed_end = 0;
    bool have_claim = false;
    for (const Key& k : hits) {
        if (have_claim && k.start < claimed_end) continue;  // overlaps a kept key
        claimed_end = k.end;
        have_claim = true;

        Finding f;
        f.offset = k.start;
        f.size = k.end - k.start;
        f.type = "der-private-key";
        f.category = "secret";
        f.label = k.label + " private key";
        f.description =
            "Embedded " + k.label +
            " private key in raw DER form (no PEM wrapper); text/pattern secret scans miss these";
        f.set_confidence(Confidence::Structural, "DER private key structurally parsed");
        out.push_back(std::move(f));
    }
    return out;
}

}  // namespace ft
