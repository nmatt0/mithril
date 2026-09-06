#include "rpm.hpp"

#include <string_view>
#include <unordered_set>

#include "reader.hpp"
#include "strutil.hpp"

namespace ft {

namespace {

// RPM header tags we read (all STRING type).
constexpr uint32_t TAG_NAME = 1000, TAG_VERSION = 1001, TAG_RELEASE = 1002, TAG_ARCH = 1022;

// Read a NUL-terminated string at `off`, bounded by `end`.
std::string cstr_at(std::span<const uint8_t> d, size_t off, size_t end) {
    std::string s;
    for (size_t i = off; i < end && i < d.size(); ++i) {
        if (d[i] == 0) break;
        s += static_cast<char>(d[i]);
    }
    return s;
}

// Parse one RPM header starting at `pos` (which points at the magic). Fills the
// component fields; returns the byte length consumed (0 = not a valid header).
size_t parse_header(const Reader& r, size_t pos, std::string& name, std::string& version,
                    std::string& release, std::string& arch) {
    // magic 8e ad e8 01, then 4 reserved bytes.
    static const uint8_t magic[4] = {0x8e, 0xad, 0xe8, 0x01};
    if (!r.matches_at(pos, std::span<const uint8_t>(magic, 4))) return 0;
    auto nindex = r.at<uint32_t>(pos + 8, Endian::Big);
    auto hsize = r.at<uint32_t>(pos + 12, Endian::Big);
    if (!nindex || !hsize) return 0;
    if (*nindex == 0 || *nindex > 65535 || *hsize > (16u << 20)) return 0;

    const size_t index_start = pos + 16;
    const size_t data_start = index_start + static_cast<size_t>(*nindex) * 16;
    const size_t data_end = data_start + *hsize;
    if (data_end > r.size()) return 0;
    auto data = r.data();

    for (uint32_t i = 0; i < *nindex; ++i) {
        size_t e = index_start + static_cast<size_t>(i) * 16;
        auto tag = r.at<uint32_t>(e, Endian::Big);
        auto off = r.at<uint32_t>(e + 8, Endian::Big);
        if (!tag || !off) continue;
        size_t soff = data_start + *off;
        if (soff >= data_end) continue;
        switch (*tag) {
            case TAG_NAME: name = cstr_at(data, soff, data_end); break;
            case TAG_VERSION: version = cstr_at(data, soff, data_end); break;
            case TAG_RELEASE: release = cstr_at(data, soff, data_end); break;
            case TAG_ARCH: arch = cstr_at(data, soff, data_end); break;
            default: break;
        }
    }
    return data_end - pos;
}

}  // namespace

std::vector<Component> parse_rpm_db(std::span<const uint8_t> data, const std::string& origin_path) {
    std::vector<Component> out;
    std::unordered_set<std::string> seen;  // dedup by name@version within the file
    Reader r(data);
    if (data.size() < 16) return out;

    for (size_t pos = 0; pos + 16 <= data.size();) {
        if (!(data[pos] == 0x8e && data[pos + 1] == 0xad && data[pos + 2] == 0xe8 &&
              data[pos + 3] == 0x01)) {
            ++pos;
            continue;
        }
        std::string name, version, release, arch;
        size_t consumed = parse_header(r, pos, name, version, release, arch);
        if (consumed == 0) {
            ++pos;
            continue;
        }
        if (!name.empty() && !version.empty()) {
            std::string full_ver = release.empty() ? version : version + "-" + release;
            if (seen.insert(name + "@" + full_ver).second) {
                Component c;
                c.name = name;
                c.version = full_ver;
                c.arch = arch;
                c.source = "rpm";
                c.origin_path = origin_path;
                c.purl = "pkg:rpm/" + name + "@" + full_ver + (arch.empty() ? "" : "?arch=" + arch);
                c.confidence = 90;
                c.evidence = "rpm header (installed)";
                out.push_back(std::move(c));
            }
        }
        pos += consumed;  // skip past this header
    }
    return out;
}

std::vector<Component> scan_rpm(const std::string& relpath, std::span<const uint8_t> data) {
    std::string_view p = relpath;
    std::string_view base = basename_of(p);
    bool is_rpm_db = (p.find("rpm/") != std::string_view::npos) &&
                     (base == "Packages" || base == "Packages.db" || base == "rpmdb.sqlite");
    if (!is_rpm_db) return {};
    return parse_rpm_db(data, relpath);
}

}  // namespace ft
