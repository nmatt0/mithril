// kallsyms.hpp — recover the builtin symbol table from a decompressed kernel image.
//
// Most production kernels are built with CONFIG_KALLSYMS=y, which embeds a
// compressed table of every built-in symbol name (the /proc/kallsyms source).
// The names are token-compressed (a 256-entry token table plus, per symbol, a
// length byte and a run of token indices), so a plain strings(1) sweep only
// recovers a lucky few. Decoding the table gives the exact, complete set of
// built-in function/data symbols — an authoritative in-image oracle for which
// kernel subsystems are compiled in (=y), even when no .config was shipped.
//
// This is a best-effort, self-anchoring decoder: it locates the token table by
// its structural invariants (256 NUL-terminated tokens followed by a 256-entry
// strictly-increasing uint16 index), then the names blob by cross-checking the
// symbol count against the markers array. On any inconsistency it returns
// nullopt rather than guessing, so a failed decode never fabricates symbols.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_set>

namespace ft {

struct Kallsyms {
    // Bare symbol names (type char stripped), e.g. "commit_creds", "nft_do_chain".
    std::unordered_set<std::string> names;
    // True when the table decoded cleanly and passed sanity checks, so the
    // *absence* of a symbol can be trusted (used to rule a subsystem out).
    bool complete = false;

    bool has(const std::string& sym) const { return names.find(sym) != names.end(); }
};

// Decode an embedded kallsyms table from a decompressed kernel image. nullopt if
// no consistent table is found. Tries 32-bit and 64-bit word sizes.
std::optional<Kallsyms> decode_kallsyms(std::span<const uint8_t> data);

}  // namespace ft
