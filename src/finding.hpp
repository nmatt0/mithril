// finding.hpp — the content-analysis result type shared by mithril's passes.
//
// A Finding describes something found *in* the content: a secret, an interesting
// file, later a config hit. SBOM components use their own model (component.hpp);
// the CVE join is downstream of that.
//
// Honesty bar (docs/engine-design.md): mithril is fully offline, so there is no
// "live" claim. Confidence is a deterministic ladder — a shape match, then a
// structural parse, then an embedded-checksum recompute. The tool asserts
// "well-formed / checksum-valid", never "live".
#pragma once

#include <cstdint>
#include <string>

namespace ft {

// Confidence ladder (0-100 with named tiers), all reachable offline:
//   pattern    keyword + shape + entropy matched
//   structural the value's own structure parses (a JWT decodes; a PEM key parses)
//   validated  an embedded checksum recomputes correctly (e.g. GitHub token CRC32)
enum class Confidence : uint8_t {
    Reject = 0,
    Pattern = 60,
    Structural = 80,
    Validated = 95,
};

inline const char* tier_name(Confidence c) {
    switch (c) {
        case Confidence::Pattern: return "pattern";
        case Confidence::Structural: return "structural";
        case Confidence::Validated: return "validated";
        case Confidence::Reject: return "reject";
    }
    return "reject";
}

struct Finding {
    size_t offset = 0;  // byte offset of the match within its file
    size_t size = 0;    // 0 = unknown/unspecified

    std::string type;      // the specific kind, e.g. "aws-access-key-id"
    std::string category;  // the pass family, e.g. "secret" / "config" / "credential-file"

    uint8_t confidence = 0;       // 0-100
    std::string confidence_tier;  // "pattern", ...
    std::string evidence;         // short human reason for the score

    // Optional descriptive fields; emitted only when non-empty.
    std::string label;        // a display value (a redacted token, a key type, a filename)
    std::string version;      // relevant for version-string findings
    std::string description;  // one-line human description

    void set_confidence(Confidence c, std::string why) {
        confidence = static_cast<uint8_t>(c);
        confidence_tier = tier_name(c);
        evidence = std::move(why);
    }
};

}  // namespace ft
