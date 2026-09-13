// fdt.cpp — read-only FDT/DTB parser. See fdt.hpp.
#include "fdt.hpp"

#include "reader.hpp"

namespace ft {

namespace {

constexpr uint32_t FDT_MAGIC = 0xD00DFEED;
constexpr uint32_t FDT_BEGIN_NODE = 1;
constexpr uint32_t FDT_END_NODE = 2;
constexpr uint32_t FDT_PROP = 3;
constexpr uint32_t FDT_NOP = 4;
constexpr uint32_t FDT_END = 9;

constexpr size_t kMaxNodes = 16384;
constexpr size_t kMaxDepth = 64;
constexpr size_t kMaxTokens = 1u << 20;

inline size_t align4(size_t n) { return (n + 3) & ~size_t(3); }

// A NUL-terminated string at `off`, bounded to `limit`. nullopt on overrun.
std::optional<std::string> cstr(std::span<const uint8_t> d, size_t off, size_t limit) {
    if (off >= limit || off >= d.size()) return std::nullopt;
    size_t end = off;
    const size_t cap = limit < d.size() ? limit : d.size();
    while (end < cap && d[end] != 0) ++end;
    if (end >= cap) return std::nullopt;  // unterminated
    return std::string(reinterpret_cast<const char*>(d.data()) + off, end - off);
}

}  // namespace

std::string FdtNode::str(std::string_view n) const {
    const FdtProp* p = find(n);
    if (!p || p->value.empty()) return {};
    const char* c = reinterpret_cast<const char*>(p->value.data());
    size_t len = p->value.size();
    // Trim to the first NUL (property values are NUL-terminated strings).
    size_t z = 0;
    while (z < len && c[z] != 0) ++z;
    return std::string(c, z);
}

std::optional<std::vector<FdtNode>> parse_fdt(std::span<const uint8_t> data) {
    Reader r(data);
    auto magic = r.at<uint32_t>(0, Endian::Big);
    if (!magic || *magic != FDT_MAGIC) return std::nullopt;
    auto totalsize = r.at<uint32_t>(4, Endian::Big);
    auto off_struct = r.at<uint32_t>(8, Endian::Big);
    auto off_strings = r.at<uint32_t>(12, Endian::Big);
    auto version = r.at<uint32_t>(20, Endian::Big);
    if (!totalsize || !off_struct || !off_strings || !version) return std::nullopt;
    if (*version < 2 || *version > 17) return std::nullopt;  // sane FDT versions
    if (*totalsize > data.size()) return std::nullopt;

    const size_t strings_base = *off_strings;
    const size_t strings_limit = *totalsize <= data.size() ? *totalsize : data.size();
    if (strings_base >= strings_limit) return std::nullopt;

    std::vector<FdtNode> nodes;
    std::vector<std::string> stack;  // path components of currently-open nodes
    size_t pos = *off_struct;
    const size_t end = strings_limit;
    size_t tokens = 0;
    bool saw_end = false;

    while (pos + 4 <= end && tokens++ < kMaxTokens) {
        auto tok = r.at<uint32_t>(pos, Endian::Big);
        if (!tok) break;
        pos += 4;
        if (*tok == FDT_NOP) continue;
        if (*tok == FDT_END) { saw_end = true; break; }
        if (*tok == FDT_BEGIN_NODE) {
            auto name = cstr(data, pos, end);
            if (!name) return std::nullopt;
            pos = align4(pos + name->size() + 1);
            if (stack.size() >= kMaxDepth || nodes.size() >= kMaxNodes) return std::nullopt;
            stack.push_back(*name);
            // Build the full path.
            std::string path = "/";
            for (size_t i = 0; i < stack.size(); ++i) {
                if (stack[i].empty()) continue;  // the root's own name is empty
                if (path.size() > 1) path += "/";
                path += stack[i];
            }
            FdtNode node;
            node.name = *name;
            node.path = path;
            nodes.push_back(std::move(node));
        } else if (*tok == FDT_END_NODE) {
            if (stack.empty()) return std::nullopt;
            stack.pop_back();
        } else if (*tok == FDT_PROP) {
            auto len = r.at<uint32_t>(pos, Endian::Big);
            auto nameoff = r.at<uint32_t>(pos + 4, Endian::Big);
            if (!len || !nameoff) return std::nullopt;
            pos += 8;
            auto pname = cstr(data, strings_base + *nameoff, strings_limit);
            if (!pname) return std::nullopt;
            auto val = r.bytes(pos, *len);
            if (!val) return std::nullopt;
            if (!nodes.empty() && !stack.empty())
                nodes.back().props.push_back({*pname, *val});
            pos = align4(pos + *len);
        } else {
            return std::nullopt;  // unknown token
        }
    }
    if (!saw_end || nodes.empty()) return std::nullopt;
    return nodes;
}

bool fdt_is_fit(const std::vector<FdtNode>& nodes) {
    for (const auto& n : nodes)
        if (n.path == "/images") return true;
    return false;
}

}  // namespace ft
