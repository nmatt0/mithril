// inflate.hpp — hand-rolled DEFLATE (RFC 1951) + gzip (RFC 1952), no zlib.
//
// mithril stays dependency-free. This is needed to reach compressed content that
// moria's extraction does not unwrap on its own: the gzip-compressed kernel
// .config embedded via CONFIG_IKCONFIG (kconfig.cpp), and any gzip blob embedded
// inside another file. Output is bounded (default 64 MiB) so a crafted stream
// cannot exhaust memory. Returns nullopt on any malformed/oversized input.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace ft {

// Inflate a raw DEFLATE stream. nullopt on error or if output would exceed max_out.
std::optional<std::vector<uint8_t>> inflate_raw(std::span<const uint8_t> in,
                                                size_t max_out = 64u << 20);

// Inflate a gzip stream (magic 1f 8b): skip the header, inflate the body.
std::optional<std::vector<uint8_t>> gzip_inflate(std::span<const uint8_t> in,
                                                 size_t max_out = 64u << 20);

}  // namespace ft
