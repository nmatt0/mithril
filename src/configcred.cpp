#include "configcred.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <optional>
#include <string_view>

#include "jsonparse.hpp"
#include "validators.hpp"

namespace ft {

namespace {

constexpr size_t kMaxFileSize = 1u << 20;   // 1 MiB: real config files are tiny
constexpr size_t kMaxValueLen = 4096;        // ignore absurdly long "values"
constexpr size_t kMaxFindings = 256;         // cap a pathological config

// Strong credential key names, normalized (lowercased, non-alnum stripped).
// Two sub-tiers differ only in how the value is judged:
//   pin-like   — device access codes / keys where a short value is legitimate
//                (a 4-digit PIN, a short passphrase). Short + numeric accepted.
//   token-like — API keys / tokens / secrets, where a real value is long or
//                decodes; a bare short word or integer there is noise, rejected.
bool is_pin_like_key(std::string_view k) {
    static const std::string_view keys[] = {
        "passwd", "password", "passcode", "pass", "passphrase", "pin", "pincode",
        "psk", "presharedkey", "sharedkey", "wpakey", "wepkey", "wifikey", "wlankey",
    };
    return std::find(std::begin(keys), std::end(keys), k) != std::end(keys);
}
bool is_token_like_key(std::string_view k) {
    static const std::string_view keys[] = {
        "secret", "apikey", "token", "authtoken", "accesstoken", "refreshtoken",
        "privatekey", "credential", "credentials", "clientsecret", "consumersecret",
        "appsecret", "sessionkey", "authkey",
    };
    return std::find(std::begin(keys), std::end(keys), k) != std::end(keys);
}

std::string normalize_key(std::string_view k) {
    std::string out;
    out.reserve(k.size());
    for (unsigned char c : k)
        if (std::isalnum(c)) out += static_cast<char>(std::tolower(c));
    return out;
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool all_same_char(const std::string& v) {
    return !v.empty() && std::all_of(v.begin(), v.end(), [&](char c) { return c == v[0]; });
}

// Values that are clearly unset / defaults / enums, never a real credential.
bool is_placeholder_value(const std::string& v) {
    if (v.empty()) return true;
    if (all_same_char(v)) return true;  // "0000", "xxxx", "----"
    if (is_false_positive(v)) return true;  // example/sample/changeme/your_/dummy/...
    static const char* words[] = {
        "admin", "administrator", "default", "password", "passwd", "pass", "none",
        "null", "nil", "na", "n/a", "root", "guest", "user", "enable", "disable",
        "enabled", "disabled", "true", "false", "yes", "no", "on", "off", "test",
        "unknown", "undefined", "empty", "set", "unset", "value",
    };
    std::string lv = lower(v);
    for (const char* w : words)
        if (lv == w) return true;
    return false;
}

bool whitespace_only(const std::string& v) {
    return std::all_of(v.begin(), v.end(),
                       [](unsigned char c) { return std::isspace(c) != 0; });
}

// Shape tests for the decode bump. base64: >=4 chars, multiple of 4 with 0-2 '='
// padding, body in the standard alphabet. hex: even length >=4, all hex digits.
bool looks_base64(const std::string& v) {
    if (v.size() < 4 || v.size() % 4 != 0) return false;
    size_t pad = 0;
    while (pad < v.size() && v[v.size() - 1 - pad] == '=') ++pad;
    if (pad > 2) return false;
    for (size_t i = 0; i + pad < v.size(); ++i) {
        char c = v[i];
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/')) return false;
    }
    return true;
}
bool looks_hex(const std::string& v) {
    if (v.size() < 4 || v.size() % 2 != 0) return false;
    return std::all_of(v.begin(), v.end(),
                       [](unsigned char c) { return std::isxdigit(c) != 0; });
}

std::vector<uint8_t> hex_decode(const std::string& v) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < v.size(); i += 2) {
        int hi = nib(v[i]), lo = nib(v[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

bool mostly_printable(const std::vector<uint8_t>& b) {
    if (b.empty()) return false;
    size_t printable = 0;
    for (uint8_t c : b)
        if (c == '\t' || (c >= 0x20 && c < 0x7F)) ++printable;
    return printable * 100 >= b.size() * 80;
}

std::string to_str(const std::vector<uint8_t>& b) {
    return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

// Finding type by key family (keeps crypto-ish PSKs separate from app secrets).
std::string type_for(std::string_view nk, bool pin_like) {
    if (nk == "psk" || nk == "presharedkey" || nk == "sharedkey" || nk == "wpakey" ||
        nk == "wepkey" || nk == "wifikey" || nk == "wlankey")
        return "config-wifi-key";
    return pin_like ? "config-password" : "config-secret";
}

struct Ctx {
    std::vector<Finding>* out;
    size_t count = 0;
};

// Judge one (key, scalar-value) pair and emit at most one finding.
void consider(Ctx& ctx, const std::string& keypath, std::string_view raw_key,
              const std::string& value, bool numeric) {
    if (ctx.count >= kMaxFindings) return;
    if (value.empty() || value.size() > kMaxValueLen) return;

    std::string nk = normalize_key(raw_key);
    bool pin_like = is_pin_like_key(nk);
    bool token_like = is_token_like_key(nk);
    if (!pin_like && !token_like) return;  // strong-key gate (v1 is strong-only)

    if (whitespace_only(value) || is_placeholder_value(value)) return;

    // Try a transform. A strong key whose value cleanly base64/hex-decodes to
    // printable text is strong evidence of an encoded credential (the encoded
    // short-PIN case), and is the structural confidence bump.
    std::string decoded;
    const char* enc = nullptr;
    if (!numeric && looks_base64(value)) {
        auto d = base64_decode(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(value.data()), value.size()));
        if (mostly_printable(d)) { decoded = to_str(d); enc = "base64"; }
    }
    if (!enc && !numeric && looks_hex(value)) {
        auto d = hex_decode(value);
        if (mostly_printable(d)) { decoded = to_str(d); enc = "hex"; }
    }
    // The decoded form must itself not be an obvious placeholder.
    if (enc && (decoded.empty() || is_placeholder_value(decoded))) { enc = nullptr; decoded.clear(); }

    // token-like keys need a substantive value: long enough, or it decoded.
    // A bare short word / integer under "token"/"secret"/"key" is rejected.
    if (token_like && !enc) {
        if (numeric) return;                 // "token": 1003 is a log/enum code, not a secret
        if (value.size() < 8) return;        // too short to be a real token without a decode
    }

    // Partition with the flat-stream engine to avoid a double report: a long,
    // no-decode raw value under a key the generic-secret rule ALSO anchors on
    // (password/passwd/secret/api_key/access_token/auth_token/private_key) is
    // that rule's job — it catches >=16 chars at >=3.5 bits. Keys the flat-stream
    // rule has no anchor for (psk, pin, wpakey, token, ...) are only ever caught
    // here, so they are never deferred regardless of length.
    auto generic_engine_covers = [](std::string_view k) {
        static const std::string_view a[] = {"password", "passwd",     "secret",
                                              "apikey",   "accesstoken", "authtoken",
                                              "privatekey"};
        return std::find(std::begin(a), std::end(a), k) != std::end(a);
    };
    if (!enc && value.size() >= 16 && token_entropy(value) >= 3.5 && generic_engine_covers(nk))
        return;

    Finding f;
    f.offset = 0;  // file-scoped; the key path localizes it
    f.size = value.size();
    f.type = type_for(nk, pin_like);
    f.category = "config-credential";
    f.label = enc ? redact(value) + " (" + enc + ")" : redact(value);
    if (enc)
        f.description = "Credential field `" + keypath + "` (" + enc + "-encoded value)";
    else
        f.description = "Credential field `" + keypath + "`";

    if (enc)
        f.set_confidence(Confidence::Structural,
                         std::string("config key + ") + enc + "-decoded value");
    else
        f.set_confidence(Confidence::Pattern, "config key + non-placeholder value");
    ctx.out->push_back(std::move(f));
    ++ctx.count;
}

// Format an integral JSON number back to text (for numeric PIN values).
std::optional<std::string> integral_number(double d) {
    if (d != d || d < 0 || d > 1e12) return std::nullopt;           // NaN / huge / negative
    if (d != static_cast<double>(static_cast<long long>(d))) return std::nullopt;  // has a fraction
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(d));
    return std::string(buf);
}

void walk(Ctx& ctx, const JsonValue& v, const std::string& path, std::string_view inherited_key);

// Dispatch a scalar/compound value that sits under `key` at `path`.
void dispatch(Ctx& ctx, const JsonValue& v, const std::string& path, std::string_view key) {
    switch (v.type) {
        case JsonValue::Type::String:
            consider(ctx, path, key, v.str, /*numeric=*/false);
            break;
        case JsonValue::Type::Number:
            if (auto s = integral_number(v.num)) consider(ctx, path, key, *s, /*numeric=*/true);
            break;
        case JsonValue::Type::Object:
        case JsonValue::Type::Array:
            walk(ctx, v, path, key);
            break;
        default:
            break;  // Null / Bool: never a credential
    }
}

void walk(Ctx& ctx, const JsonValue& v, const std::string& path, std::string_view inherited_key) {
    if (ctx.count >= kMaxFindings) return;
    if (v.type == JsonValue::Type::Object) {
        for (const auto& m : v.obj) {
            std::string child = path.empty() ? m.key : path + "." + m.key;
            dispatch(ctx, m.value, child, m.key);  // the member key is authoritative
        }
    } else if (v.type == JsonValue::Type::Array) {
        // Scalar elements inherit the array's own key, so `"pins":["8604"]`
        // is covered; object/array elements carry their own keys as usual.
        for (const auto& e : v.arr) {
            std::string child = path + "[]";
            dispatch(ctx, e, child, inherited_key);
        }
    }
}

}  // namespace

std::vector<Finding> scan_config_credentials(const std::string& relpath,
                                             std::span<const uint8_t> data) {
    (void)relpath;  // v1 keys off content, not extension; relpath reserved for later tiers
    std::vector<Finding> out;
    if (data.empty() || data.size() > kMaxFileSize) return out;

    // Cheap sniff: a JSON document starts with '{' or '[' after whitespace.
    size_t i = 0;
    while (i < data.size() && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' ||
                               data[i] == '\r'))
        ++i;
    if (i >= data.size() || (data[i] != '{' && data[i] != '[')) return out;

    auto parsed = json_parse(std::string_view(reinterpret_cast<const char*>(data.data()),
                                              data.size()));
    if (!parsed) return out;  // not well-formed JSON -> not our file (strong gate)

    Ctx ctx{&out, 0};
    walk(ctx, *parsed, "", "");
    return out;
}

}  // namespace ft
