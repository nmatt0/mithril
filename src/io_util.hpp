// io_util.hpp — small shared file I/O helper (header-only).
//
// One canonical whole-file read, replacing three near-identical copies that
// lived in cve.cpp / cveupdate.cpp / userrules.cpp. Exception-safe: the FILE is
// closed on every path (RAII), including if a read or append throws.
#pragma once

#include <cstdio>
#include <memory>
#include <optional>
#include <string>

namespace ft {

// Read an entire file into a string. Returns nullopt if the file cannot be
// opened; an empty (but present) file yields an empty string.
inline std::optional<std::string> read_file(const std::string& path) {
    std::unique_ptr<std::FILE, int (*)(std::FILE*)> f(std::fopen(path.c_str(), "rb"), std::fclose);
    if (!f) return std::nullopt;
    std::string out;
    char buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f.get())) > 0) out.append(buf, n);
    return out;
}

}  // namespace ft
