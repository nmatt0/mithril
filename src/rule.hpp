// rule.hpp — the one rule model that drives the engine (docs/engine-design.md).
//
// Two rule shapes cover every discovery job. Built-in rules are C++ instances of
// these structs (so they bind directly to code validators in validators.hpp); a
// user rule file will later deserialize into the SAME structs, limited to the
// safe declarative subset. Built-ins and user rules are the same type — the file
// is just another source feeding the engine.
#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "finding.hpp"
#include "reader.hpp"

namespace ft {

// What a content rule's matcher returns at an anchor offset. `len` is the token
// length measured from the anchor offset; 0 (i.e. nullopt) means "not a match".
struct Match {
    size_t len = 0;
    Confidence confidence = Confidence::Pattern;
    std::string evidence;
    std::string label;        // display/redacted value; empty -> engine redacts the token
    std::string version;      // optional
    std::string description;  // optional per-hit description
};

// M2/M3: literal `anchors` are added to the shared Aho-Corasick automaton; on a
// hit the engine runs `matcher` on the bytes at that offset (bounded by the
// matcher itself). The engine applies the common post-filters (false-positive
// wordlist; entropy gate when `min_entropy > 0`) so matchers stay small.
struct ContentRule {
    std::string type;
    std::string category;  // "secret" | "config" | ...
    std::vector<std::string> anchors;
    std::function<std::optional<Match>(const Reader&, size_t)> matcher;
    double min_entropy = 0.0;  // 0 = no entropy gate (e.g. structurally-validated rules)
    std::string description;   // default description when a Match leaves its own empty
};

// M1: a glob over the file's path selects the rule.
enum class PathAction {
    FlagNotable,  // record the file as a notable finding (a credential/crypto/config file)
};

struct PathRule {
    std::string glob;       // '*' matches within a path segment, '**' across segments, '?' one char
    PathAction action = PathAction::FlagNotable;
    std::string category;   // "credential-file" | "crypto" | "config"
    std::string type;       // finding type, e.g. "shadow-file"
    std::string description;
};

// Glob match against a whole relative path. '*' does not cross '/'; '**' does;
// '?' matches a single non-'/' char. Anchored at both ends.
bool glob_match(const std::string& glob, const std::string& path);

}  // namespace ft
