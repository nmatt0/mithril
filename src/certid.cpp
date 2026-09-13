// certid.cpp — X.509 cert extraction + fingerprinting. See certid.hpp.
#include "certid.hpp"

#include <algorithm>
#include <optional>
#include <string_view>

#include "sha256.hpp"

namespace ft {

namespace {

// EFI_CERT_X509_GUID (A5C059A1-94E4-4AA7-87B5-AB155C2BF072), on-disk bytes.
constexpr uint8_t kX509Guid[16] = {0xA1, 0x59, 0xC0, 0xA5, 0xE4, 0x94, 0xA7, 0x4A,
                                   0x87, 0xB5, 0xAB, 0x15, 0x5C, 0x2B, 0xF0, 0x72};

struct Der {
    uint8_t tag;
    size_t content;  // offset of the value
    size_t end;      // offset just past the value
};

// Parse one DER TLV at `i`. Bounds-checked; nullopt on any overrun.
std::optional<Der> der_at(std::span<const uint8_t> d, size_t i) {
    if (i + 2 > d.size()) return std::nullopt;
    uint8_t tag = d[i];
    size_t j = i + 1;
    size_t len = d[j++];
    if (len & 0x80) {
        size_t n = len & 0x7F;
        if (n == 0 || n > 8 || j + n > d.size()) return std::nullopt;
        len = 0;
        for (size_t k = 0; k < n; ++k) len = (len << 8) | d[j++];
    }
    if (len > d.size() || j + len > d.size()) return std::nullopt;
    return Der{tag, j, j + len};
}

uint32_t le32(std::span<const uint8_t> d, size_t o) {
    return uint32_t(d[o]) | (uint32_t(d[o + 1]) << 8) | (uint32_t(d[o + 2]) << 16) |
           (uint32_t(d[o + 3]) << 24);
}

std::vector<uint8_t> b64decode(const std::string& s) {
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
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

}  // namespace

std::string cert_fingerprint(std::span<const uint8_t> der_cert) {
    if (der_cert.empty()) return {};
    return sha256_hex(der_cert).substr(0, 32);
}

std::vector<std::vector<uint8_t>> certs_in_efi_signature_list(std::span<const uint8_t> data) {
    std::vector<std::vector<uint8_t>> out;
    size_t pos = 0;
    for (int lists = 0; lists < 256 && pos + 28 <= data.size(); ++lists) {
        const size_t list_size = le32(data, pos + 16);
        const size_t hdr_size = le32(data, pos + 20);
        const size_t sig_size = le32(data, pos + 24);
        if (list_size < 28 + hdr_size || list_size > data.size() - pos || sig_size <= 16) break;
        if (sig_size > list_size) break;
        const bool is_x509 = std::equal(kX509Guid, kX509Guid + 16, data.begin() + pos);
        if (is_x509) {
            size_t e = pos + 28 + hdr_size;
            const size_t list_end = pos + list_size;
            for (int i = 0; i < 4096 && e + sig_size <= list_end; ++i) {
                // EFI_SIGNATURE_DATA: 16-byte owner GUID, then the DER cert.
                const size_t cert_off = e + 16;
                const size_t cert_len = sig_size - 16;
                if (cert_off + cert_len <= data.size())
                    out.emplace_back(data.begin() + cert_off, data.begin() + cert_off + cert_len);
                e += sig_size;
            }
        }
        pos += list_size;
    }
    return out;
}

std::vector<uint8_t> cert_from_pkcs7(std::span<const uint8_t> der) {
    auto outer = der_at(der, 0);
    if (!outer || outer->tag != 0x30) return {};
    size_t i = outer->content;
    while (i < outer->end) {
        auto node = der_at(der, i);
        if (!node) break;
        if (node->tag == 0xA0) {  // certificates [0] IMPLICIT
            auto cert = der_at(der, node->content);
            if (cert && cert->tag == 0x30)
                return std::vector<uint8_t>(der.begin() + node->content, der.begin() + cert->end);
            break;
        }
        i = node->end;
    }
    return {};
}

std::vector<uint8_t> cert_from_any(std::span<const uint8_t> data) {
    // PEM certificate?
    static const char kBegin[] = "-----BEGIN CERTIFICATE-----";
    std::string_view sv(reinterpret_cast<const char*>(data.data()),
                        std::min<size_t>(data.size(), 1u << 20));
    if (size_t b = sv.find(kBegin); b != std::string_view::npos) {
        size_t body = b + sizeof(kBegin) - 1;
        size_t e = sv.find("-----END CERTIFICATE-----", body);
        if (e != std::string_view::npos) {
            auto der = b64decode(std::string(sv.substr(body, e - body)));
            if (!der.empty()) return der;
        }
    }
    // Bare DER certificate: a SEQUENCE that itself begins with a SEQUENCE (tbs).
    if (data.size() >= 4 && data[0] == 0x30) {
        auto outer = der_at(data, 0);
        if (outer) {
            auto tbs = der_at(data, outer->content);
            if (tbs && tbs->tag == 0x30)
                return std::vector<uint8_t>(data.begin(), data.begin() + outer->end);
        }
    }
    return {};
}

}  // namespace ft
