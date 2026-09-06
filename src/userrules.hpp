// userrules.hpp — load user-defined rules from a JSON file into the same rule
// structs the built-ins use (docs/engine-design.md: "built-ins and user rules
// are the same type; the file is just another source").
//
// Users get the safe declarative subset — path globs and content keyword/regex
// with a category — not the code-level validators (CRC32/JWT/PEM), which stay
// built in. Any regex runs only on the bounded window an anchor produces
// (match_continuous, anchored at the anchor), so it inherits the engine's
// ReDoS-safe posture.
//
// File shape:
//   {
//     "path_rules": [
//       {"glob":"**/*.p12","category":"crypto","type":"pkcs12","description":"..."}
//     ],
//     "content_rules": [
//       {"type":"vendor-cred","category":"secret","anchors":["ADMIN_PW"],
//        "regex":"ADMIN_PW\\s*=\\s*(\\S+)","min_entropy":0,"description":"..."},
//       {"type":"internal-host","category":"config","anchors":["update.corp.local"]}
//     ]
//   }
// A content rule with a `regex` extracts capture group 1 (if present) as the
// label; without a `regex` it is a keyword-presence match on the anchor.
#pragma once

#include <string>
#include <vector>

#include "rule.hpp"

namespace ft {

struct UserRules {
    std::vector<ContentRule> content;
    std::vector<PathRule> paths;
    std::string error;  // non-empty if the file could not be loaded/parsed
    bool ok() const { return error.empty(); }
};

// Load and compile a user rule file. On any error, `error` is set and the
// vectors are empty. Regexes are validated (and compiled) at load time.
UserRules load_user_rules(const std::string& path);

// Parse+compile rules from an in-memory JSON string (the core of load_user_rules,
// exposed for testing without file I/O).
UserRules parse_user_rules(const std::string& text);

}  // namespace ft
