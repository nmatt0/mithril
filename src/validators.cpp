#include "validators.hpp"

#include <algorithm>
#include <string_view>

#include "crc32.hpp"
#include "entropy.hpp"
#include "jsonparse.hpp"

namespace ft {

size_t run(const Reader& r, size_t off, size_t max, bool (*pred)(uint8_t)) {
    size_t n = 0;
    while (n < max) {
        auto b = r.bytes(off + n, 1);
        if (!b || !pred((*b)[0])) break;
        ++n;
    }
    return n;
}

std::string token_str(const Reader& r, size_t off, size_t len) {
    std::string s;
    auto b = r.bytes(off, len);
    if (b)
        for (uint8_t c : *b) s += static_cast<char>(c);
    return s;
}

std::string redact(const std::string& tok) {
    if (tok.size() <= 10) return tok.substr(0, 3) + "...";
    return tok.substr(0, 4) + "..." + tok.substr(tok.size() - 4);
}

static std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool is_false_positive(const std::string& tok) {
    static const char* words[] = {"example", "sample", "changeme", "placeholder", "your_",
                                  "yourkey", "test_key", "notreal", "redacted", "dummy",
                                  "xxxxxx", "aaaaaa", "000000", "<your", "insert_"};
    std::string lt = lower(tok);
    for (const char* w : words)
        if (lt.find(w) != std::string::npos) return true;
    return false;
}

double token_entropy(const std::string& tok) {
    return string_entropy(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(tok.data()),
                                                   tok.size()));
}

std::vector<uint8_t> base64_decode(std::span<const uint8_t> in) {
    auto val = [](uint8_t c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    int buf = 0, bits = 0;
    for (uint8_t c : in) {
        if (c == '=') break;
        int v = val(c);
        if (v < 0) break;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

std::vector<uint8_t> base64url_decode(std::span<const uint8_t> in) {
    auto val = [](uint8_t c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-') return 62;
        if (c == '_') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    int buf = 0, bits = 0;
    for (uint8_t c : in) {
        if (c == '=') break;
        int v = val(c);
        if (v < 0) break;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

// ---- GitHub token CRC32 checksum ----
// base62 alphabet used by GitHub's checksum scheme.
static const char* kBase62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

std::string base62_crc32_6(std::span<const uint8_t> body) {
    uint32_t crc = crc32_ieee(body);
    char out[6];
    for (int i = 5; i >= 0; --i) {
        out[i] = kBase62[crc % 62];
        crc /= 62;
    }
    return std::string(out, out + 6);
}

bool github_token_crc_ok(const std::string& token, size_t prefix_len) {
    // token = prefix(prefix_len) + body + checksum(6). Need at least prefix+1+6.
    if (token.size() < prefix_len + 7) return false;
    std::string_view sv(token);
    std::string_view body = sv.substr(prefix_len, sv.size() - prefix_len - 6);
    std::string_view checksum = sv.substr(sv.size() - 6);
    std::string want =
        base62_crc32_6(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(body.data()),
                                                body.size()));
    return checksum == want;
}

// ---- JWT ----
JwtInfo jwt_inspect(const std::string& token, long long now_epoch) {
    JwtInfo info;
    size_t d1 = token.find('.');
    if (d1 == std::string::npos) return info;
    size_t d2 = token.find('.', d1 + 1);
    std::string_view header = std::string_view(token).substr(0, d1);
    std::string_view payload = (d2 == std::string::npos)
                                   ? std::string_view(token).substr(d1 + 1)
                                   : std::string_view(token).substr(d1 + 1, d2 - d1 - 1);

    auto dec = [](std::string_view s) {
        auto v = base64url_decode(
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()), s.size()));
        return std::string(v.begin(), v.end());
    };
    auto hjson = json_parse(dec(header));
    auto pjson = json_parse(dec(payload));
    if (!hjson || !hjson->is_object()) return info;
    info.ok = true;
    info.alg = hjson->get_str("alg");
    if (pjson && pjson->is_object()) {
        const JsonValue* e = pjson->find("exp");
        if (e && e->type == JsonValue::Type::Number) {
            info.exp = static_cast<long long>(e->num);
            if (now_epoch > 0 && info.exp > 0 && info.exp < now_epoch) info.expired = true;
        }
    }
    return info;
}

// ---- PEM ----
std::string pem_key_type(const std::string& header_line) {
    // "-----BEGIN RSA PRIVATE KEY-----" -> "RSA"; "-----BEGIN PRIVATE KEY-----" -> "".
    const std::string begin = "-----BEGIN ";
    const std::string tail = " PRIVATE KEY-----";
    if (header_line.compare(0, begin.size(), begin) != 0) return "";
    size_t tpos = header_line.find(tail);
    if (tpos == std::string::npos || tpos < begin.size()) return "";
    return header_line.substr(begin.size(), tpos - begin.size());
}

}  // namespace ft
