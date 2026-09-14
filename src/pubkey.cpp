// pubkey.cpp — recover public keys from firmware content. See pubkey.hpp.
//
// Text-anchored, like the secrets engine: PEM armor and OpenSSH public-key lines
// are what carry keys in real firmware (certs, ssh_host_*_key.pub, authorized_keys),
// far more often than a bare DER blob in a binary. A whole-file bare DER
// certificate or SubjectPublicKeyInfo is also handled. All DER parsing is a
// bounded ASN.1 TLV walk; base64 and SSH-wire decoding are bounds-checked.
#include "pubkey.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <string_view>

#include "certid.hpp"
#include "sha256.hpp"

namespace ft {

const char* origin_name(KeyOrigin o) {
    switch (o) {
        case KeyOrigin::Certificate: return "certificate";
        case KeyOrigin::SshPublicKey: return "ssh-public-key";
        case KeyOrigin::PublicKeyInfo: return "public-key";
        case KeyOrigin::PrivateKey: return "private-key";
    }
    return "public-key";
}

namespace {

// ---- ASN.1 DER TLV (bounded) ----------------------------------------------
struct Der {
    uint8_t tag = 0;
    size_t body = 0;  // offset of the value
    size_t end = 0;   // offset just past the value
    size_t len = 0;
};

std::optional<Der> der_at(std::span<const uint8_t> d, size_t i) {
    if (i + 2 > d.size()) return std::nullopt;
    uint8_t tag = d[i];
    size_t j = i + 1;
    size_t len = d[j++];
    if (len & 0x80) {
        size_t n = len & 0x7F;
        if (n == 0 || n > 4 || j + n > d.size()) return std::nullopt;
        len = 0;
        for (size_t k = 0; k < n; ++k) len = (len << 8) | d[j++];
    }
    if (j + len > d.size() || j + len < j) return std::nullopt;
    return Der{tag, j, j + len, len};
}

bool oid_eq(std::span<const uint8_t> d, const Der& t, std::span<const uint8_t> want) {
    if (t.tag != 0x06 || t.len != want.size()) return false;
    return std::equal(want.begin(), want.end(), d.begin() + t.body);
}

constexpr uint8_t OID_RSA[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
constexpr uint8_t OID_EC[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
constexpr uint8_t OID_DSA[] = {0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01};
constexpr uint8_t OID_ED25519[] = {0x2B, 0x65, 0x70};
constexpr uint8_t OID_ED448[] = {0x2B, 0x65, 0x71};
constexpr uint8_t OID_P256[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
constexpr uint8_t OID_P384[] = {0x2B, 0x81, 0x04, 0x00, 0x22};
constexpr uint8_t OID_P521[] = {0x2B, 0x81, 0x04, 0x00, 0x23};
constexpr uint8_t OID_SECP256K1[] = {0x2B, 0x81, 0x04, 0x00, 0x0A};

std::string curve_from_oid(std::span<const uint8_t> d, const Der& oid) {
    if (oid_eq(d, oid, OID_P256)) return "secp256r1";
    if (oid_eq(d, oid, OID_P384)) return "secp384r1";
    if (oid_eq(d, oid, OID_P521)) return "secp521r1";
    if (oid_eq(d, oid, OID_SECP256K1)) return "secp256k1";
    return "";
}

// Minimal big-endian magnitude of a DER INTEGER's value (strip all leading 0x00).
std::vector<uint8_t> int_magnitude(std::span<const uint8_t> d, const Der& i) {
    size_t s = i.body;
    while (s < i.end && d[s] == 0x00) ++s;
    return std::vector<uint8_t>(d.begin() + s, d.begin() + i.end);
}

size_t bit_length(std::span<const uint8_t> be) {
    size_t s = 0;
    while (s < be.size() && be[s] == 0x00) ++s;
    if (s >= be.size()) return 0;
    size_t bits = (be.size() - s - 1) * 8;
    uint8_t top = be[s];
    while (top) { ++bits; top >>= 1; }
    return bits;
}

uint64_t int_u64(std::span<const uint8_t> d, const Der& i) {
    auto m = int_magnitude(d, i);
    if (m.empty() || m.size() > 8) return 0;
    uint64_t v = 0;
    for (uint8_t b : m) v = (v << 8) | b;
    return v;
}

std::string hexpre(std::span<const uint8_t> bytes) { return sha256_hex(bytes).substr(0, 32); }

// Fill RSA fields of `k` from an `RSAPublicKey` DER SEQ { INTEGER n, INTEGER e }.
bool fill_rsa(std::span<const uint8_t> d, const Der& seq, PublicKey& k) {
    auto n = der_at(d, seq.body);
    if (!n || n->tag != 0x02) return false;
    auto e = der_at(d, n->end);
    if (!e || e->tag != 0x02) return false;
    k.algo = "RSA";
    k.n = int_magnitude(d, *n);
    k.bits = bit_length(k.n);
    k.e_be = int_magnitude(d, *e);
    k.e = int_u64(d, *e);
    k.fp_modn = hexpre(k.n);
    return !k.n.empty();
}

// Parse a SubjectPublicKeyInfo SEQ { AlgId SEQ { OID [,params] }, BIT STRING }.
// Fills algo/curve/RSA fields. Returns false if it is not a recognizable SPKI.
bool parse_spki(std::span<const uint8_t> d, const Der& spki, PublicKey& k) {
    auto alg = der_at(d, spki.body);
    if (!alg || alg->tag != 0x30) return false;
    auto oid = der_at(d, alg->body);
    if (!oid || oid->tag != 0x06) return false;
    auto bitstr = der_at(d, alg->end);
    if (!bitstr || bitstr->tag != 0x03 || bitstr->len < 1) return false;

    if (oid_eq(d, *oid, OID_RSA)) {
        // BIT STRING: 1 unused-bits byte, then DER RSAPublicKey.
        auto inner = der_at(d, bitstr->body + 1);
        if (!inner || inner->tag != 0x30) return false;
        return fill_rsa(d, *inner, k);
    }
    if (oid_eq(d, *oid, OID_EC)) {
        k.algo = "EC";
        auto params = der_at(d, oid->end);
        if (params && params->tag == 0x06) k.curve = curve_from_oid(d, *params);
        return true;
    }
    if (oid_eq(d, *oid, OID_DSA)) {
        k.algo = "DSA";
        // params SEQ { p, q, g }; p's bit length is the key strength.
        auto params = der_at(d, oid->end);
        if (params && params->tag == 0x30) {
            auto p = der_at(d, params->body);
            if (p && p->tag == 0x02) k.bits = bit_length(int_magnitude(d, *p));
        }
        return true;
    }
    if (oid_eq(d, *oid, OID_ED25519)) { k.algo = "Ed25519"; k.bits = 256; return true; }
    if (oid_eq(d, *oid, OID_ED448)) { k.algo = "Ed448"; k.bits = 448; return true; }
    return false;
}

// A DER X.509 certificate: SEQ { tbsCertificate SEQ {...}, sigAlg, sig }. Find the
// SubjectPublicKeyInfo inside tbs by trying each child SEQUENCE (issuer/subject are
// also SEQUENCEs, but only the SPKI parses as one). Fingerprint = SHA-256 of DER.
std::optional<PublicKey> parse_cert(std::span<const uint8_t> der) {
    auto outer = der_at(der, 0);
    if (!outer || outer->tag != 0x30) return std::nullopt;
    auto tbs = der_at(der, outer->body);
    if (!tbs || tbs->tag != 0x30) return std::nullopt;
    for (size_t i = tbs->body; i < tbs->end;) {
        auto child = der_at(der, i);
        if (!child) break;
        if (child->tag == 0x30) {
            PublicKey k;
            if (parse_spki(der, *child, k)) {
                k.origin = KeyOrigin::Certificate;
                k.fp_der = hexpre(der);
                return k;
            }
        }
        i = child->end;
    }
    return std::nullopt;
}

// A DER public key: a SubjectPublicKeyInfo, or a bare PKCS#1 RSAPublicKey.
std::optional<PublicKey> parse_pub_der(std::span<const uint8_t> der, KeyOrigin origin) {
    auto outer = der_at(der, 0);
    if (!outer || outer->tag != 0x30) return std::nullopt;
    PublicKey k;
    if (parse_spki(der, *outer, k)) {
        k.origin = origin;
        k.fp_der = hexpre(der);
        return k;
    }
    // Bare PKCS#1 RSAPublicKey: SEQ { INTEGER n, INTEGER e }.
    if (fill_rsa(der, *outer, k)) {
        k.origin = origin;
        k.fp_der = hexpre(der);
        return k;
    }
    return std::nullopt;
}

// The public half of a private key: for RSA, RSAPrivateKey SEQ { ver, n, e, ... }.
// PKCS#8 wraps that in an OCTET STRING after the AlgId. Non-RSA -> algo only.
std::optional<PublicKey> parse_priv_der(std::span<const uint8_t> der) {
    auto outer = der_at(der, 0);
    if (!outer || outer->tag != 0x30) return std::nullopt;
    auto ver = der_at(der, outer->body);
    if (!ver || ver->tag != 0x02) return std::nullopt;
    auto nxt = der_at(der, ver->end);
    if (!nxt) return std::nullopt;

    PublicKey k;
    if (nxt->tag == 0x02) {  // PKCS#1 RSAPrivateKey: ver, n, e, d, ...
        auto e = der_at(der, nxt->end);
        if (!e || e->tag != 0x02) return std::nullopt;
        k.algo = "RSA";
        k.n = int_magnitude(der, *nxt);
        k.bits = bit_length(k.n);
        k.e_be = int_magnitude(der, *e);
        k.e = int_u64(der, *e);
        k.fp_modn = hexpre(k.n);
        if (k.n.empty()) return std::nullopt;
        k.origin = KeyOrigin::PrivateKey;
        return k;
    }
    if (nxt->tag == 0x30) {  // PKCS#8 PrivateKeyInfo: AlgId, then privateKey OCTET STRING
        auto oid = der_at(der, nxt->body);
        if (!oid || oid->tag != 0x06) return std::nullopt;
        auto oct = der_at(der, nxt->end);
        if (!oct || oct->tag != 0x04) return std::nullopt;
        if (oid_eq(der, *oid, OID_RSA)) {
            auto inner = der_at(der, oct->body);  // RSAPrivateKey
            if (!inner || inner->tag != 0x30) return std::nullopt;
            auto iv = der_at(der, inner->body);
            if (!iv || iv->tag != 0x02) return std::nullopt;
            auto n = der_at(der, iv->end);
            auto e = n ? der_at(der, n->end) : std::nullopt;
            if (!n || n->tag != 0x02 || !e || e->tag != 0x02) return std::nullopt;
            k.algo = "RSA";
            k.n = int_magnitude(der, *n);
            k.bits = bit_length(k.n);
            k.e_be = int_magnitude(der, *e);
            k.e = int_u64(der, *e);
            k.fp_modn = hexpre(k.n);
            if (k.n.empty()) return std::nullopt;
            k.origin = KeyOrigin::PrivateKey;
            return k;
        }
        if (oid_eq(der, *oid, OID_EC)) { k.algo = "EC"; k.origin = KeyOrigin::PrivateKey; return k; }
        if (oid_eq(der, *oid, OID_ED25519)) {
            k.algo = "Ed25519"; k.bits = 256; k.origin = KeyOrigin::PrivateKey; return k;
        }
    }
    return std::nullopt;
}

// ---- base64 (standard alphabet) -------------------------------------------
std::vector<uint8_t> b64decode(std::string_view s) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    int acc = 0, bits = 0;
    for (char c : s) {
        int v = val(c);
        if (v < 0) continue;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back(uint8_t((acc >> bits) & 0xFF)); }
    }
    return out;
}

// ---- SSH wire ("string"/mpint = uint32 length + bytes) --------------------
std::optional<PublicKey> parse_ssh_blob(std::span<const uint8_t> blob, size_t off) {
    std::vector<std::span<const uint8_t>> fields;
    size_t i = 0;
    for (int guard = 0; guard < 16 && i + 4 <= blob.size(); ++guard) {
        uint32_t n = (uint32_t(blob[i]) << 24) | (uint32_t(blob[i + 1]) << 16) |
                     (uint32_t(blob[i + 2]) << 8) | blob[i + 3];
        i += 4;
        if (n > blob.size() - i) return std::nullopt;
        fields.push_back(blob.subspan(i, n));
        i += n;
    }
    if (fields.empty()) return std::nullopt;
    std::string_view type(reinterpret_cast<const char*>(fields[0].data()), fields[0].size());

    PublicKey k;
    k.origin = KeyOrigin::SshPublicKey;
    k.offset = off;
    k.fp_ssh = hexpre(blob);
    if (type == "ssh-rsa" && fields.size() >= 3) {
        k.algo = "RSA";
        std::span<const uint8_t> e = fields[1], n = fields[2];
        while (!n.empty() && n.front() == 0x00) n = n.subspan(1);  // mpint sign pad
        k.n.assign(n.begin(), n.end());
        k.bits = bit_length(k.n);
        while (!e.empty() && e.front() == 0x00) e = e.subspan(1);
        k.e_be.assign(e.begin(), e.end());
        if (e.size() <= 8) { for (uint8_t b : e) k.e = (k.e << 8) | b; }
        k.fp_modn = hexpre(k.n);
    } else if (type == "ssh-dss") {
        k.algo = "DSA";
        if (fields.size() >= 2) {  // p is the first param
            std::span<const uint8_t> p = fields[1];
            while (!p.empty() && p.front() == 0x00) p = p.subspan(1);
            k.bits = bit_length(p);
        }
    } else if (type == "ssh-ed25519") {
        k.algo = "Ed25519"; k.bits = 256;
    } else if (type.rfind("ecdsa-sha2-", 0) == 0) {
        k.algo = "EC";
        if (fields.size() >= 2)
            k.curve.assign(reinterpret_cast<const char*>(fields[1].data()), fields[1].size());
    } else {
        return std::nullopt;
    }
    return k;
}

void set_label(PublicKey& k) {
    std::string a = k.algo;
    if (!k.curve.empty() && k.algo == "EC") a += " " + k.curve;
    else if (k.algo == "RSA" && k.bits) a = "RSA-" + std::to_string(k.bits);
    else if (k.algo == "DSA" && k.bits) a = "DSA-" + std::to_string(k.bits);
    k.label = a + " " + origin_name(k.origin);
}

// ---- PEM block scan --------------------------------------------------------
struct Pem {
    std::string kind;                  // "CERTIFICATE" / "PUBLIC KEY" / "... PRIVATE KEY"
    std::vector<uint8_t> der;          // decoded body
    size_t offset = 0;
};

std::vector<Pem> find_pem(std::string_view text) {
    std::vector<Pem> out;
    size_t pos = 0;
    static const std::string_view begin = "-----BEGIN ";
    while (out.size() < 4096) {
        size_t b = text.find(begin, pos);
        if (b == std::string_view::npos) break;
        size_t nl = text.find("-----", b + begin.size());
        if (nl == std::string_view::npos) break;
        std::string kind(text.substr(b + begin.size(), nl - (b + begin.size())));
        std::string end_marker = "-----END " + kind + "-----";
        size_t body = nl + 5;
        size_t e = text.find(end_marker, body);
        if (e == std::string_view::npos) { pos = nl + 5; continue; }
        auto der = b64decode(text.substr(body, e - body));
        if (!der.empty()) out.push_back({std::move(kind), std::move(der), b});
        pos = e + end_marker.size();
    }
    return out;
}

bool is_private_pem(const std::string& kind) {
    return kind.find("PRIVATE KEY") != std::string::npos;
}

}  // namespace

std::vector<PublicKey> extract_public_keys(std::span<const uint8_t> data) {
    std::vector<PublicKey> out;
    if (data.size() < 8) return out;

    std::string_view text(reinterpret_cast<const char*>(data.data()),
                          std::min<size_t>(data.size(), 8u << 20));

    // 1. PEM blocks (certificates, public keys, private keys).
    for (auto& pem : find_pem(text)) {
        std::optional<PublicKey> k;
        if (pem.kind == "CERTIFICATE") {
            k = parse_cert(pem.der);
        } else if (is_private_pem(pem.kind)) {
            k = parse_priv_der(pem.der);
        } else {  // PUBLIC KEY / RSA PUBLIC KEY / ...
            k = parse_pub_der(pem.der, KeyOrigin::PublicKeyInfo);
        }
        if (k) { k->offset = pem.offset; set_label(*k); out.push_back(std::move(*k)); }
    }

    // 2. OpenSSH public-key lines: "<type> <base64> [comment]".
    static const std::array<std::string_view, 6> ssh_types = {
        "ssh-rsa ", "ssh-ed25519 ", "ssh-dss ", "ecdsa-sha2-nistp256 ",
        "ecdsa-sha2-nistp384 ", "ecdsa-sha2-nistp521 "};
    for (std::string_view t : ssh_types) {
        size_t pos = 0;
        while (true) {
            size_t p = text.find(t, pos);
            if (p == std::string_view::npos) break;
            pos = p + t.size();
            // Guard: start of line (or start of buffer).
            if (p != 0 && text[p - 1] != '\n' && text[p - 1] != '\r' && text[p - 1] != ' ') continue;
            size_t bstart = p + t.size();
            size_t bend = bstart;
            while (bend < text.size() && text[bend] != ' ' && text[bend] != '\n' &&
                   text[bend] != '\r' && text[bend] != '\0')
                ++bend;
            auto blob = b64decode(text.substr(bstart, bend - bstart));
            if (blob.size() >= 8) {
                if (auto k = parse_ssh_blob(blob, p)) { set_label(*k); out.push_back(std::move(*k)); }
            }
        }
    }

    // 3. Whole-buffer bare DER (a .der/.crt file, or a DER SPKI).
    if (!data.empty() && data[0] == 0x30) {
        if (auto k = parse_cert(data)) { set_label(*k); out.push_back(std::move(*k)); }
        else if (auto k2 = parse_pub_der(data, KeyOrigin::PublicKeyInfo)) {
            set_label(*k2); out.push_back(std::move(*k2));
        }
    }

    // 4. EFI_SIGNATURE_LIST wrapper (an extracted UEFI Secure Boot variable —
    //    PK/KEK/db): unwrap its X.509 certificates so their keys are analyzed too.
    static const uint8_t kEfiCertX509[16] = {0xA1, 0x59, 0xC0, 0xA5, 0xE4, 0x94, 0xA7, 0x4A,
                                             0x87, 0xB5, 0xAB, 0x15, 0x5C, 0x2B, 0xF0, 0x72};
    if (data.size() >= 44 && std::equal(kEfiCertX509, kEfiCertX509 + 16, data.begin())) {
        for (auto& der : certs_in_efi_signature_list(data)) {
            if (auto k = parse_cert(der)) {
                k->origin = KeyOrigin::Certificate;
                set_label(*k);
                out.push_back(std::move(*k));
            }
        }
    }

    return out;
}

}  // namespace ft
