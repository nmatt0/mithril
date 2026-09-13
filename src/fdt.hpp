// fdt.hpp — a small, read-only Flattened Device Tree (FDT/DTB) parser.
//
// mithril owns its own FDT reader (it walks any tree standalone, with no
// build-time dependency on moria). This parses a device-tree blob or a U-Boot
// FIT (which is an FDT) into a flat list of nodes with full paths and their
// properties, for the boot-security analyzers (bootargs, hardware fingerprint,
// verified-boot posture). All fields are big-endian; every read is bounds-checked
// through Reader, and the walk is capped so a malformed tree cannot run away.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ft {

struct FdtProp {
    std::string name;
    std::span<const uint8_t> value;  // borrows the input buffer (valid for its lifetime)
};

struct FdtNode {
    std::string path;   // full path, e.g. "/images/kernel-1" ("/" for the root)
    std::string name;   // this node's own name ("" for the root)
    std::vector<FdtProp> props;

    const FdtProp* find(std::string_view n) const {
        for (const auto& p : props)
            if (p.name == n) return &p;
        return nullptr;
    }
    // A property read as a NUL-terminated string (empty if absent/non-string).
    std::string str(std::string_view n) const;
    bool has(std::string_view n) const { return find(n) != nullptr; }
};

// Parse the FDT at the start of `data`. nullopt if it is not a valid FDT header.
// Nodes are returned in depth-first order (root first).
std::optional<std::vector<FdtNode>> parse_fdt(std::span<const uint8_t> data);

// A FIT is an FDT whose root has an `/images` child.
bool fdt_is_fit(const std::vector<FdtNode>& nodes);

}  // namespace ft
