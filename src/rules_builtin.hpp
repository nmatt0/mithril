// rules_builtin.hpp — mithril's built-in rule set (C++ instances of the rule
// model in rule.hpp). Content rules are the secret detectors (M2 anchors + M3
// matchers composing validators.hpp); path rules flag credential/crypto/config
// files. A user rule file will later add to these via the same structs.
#pragma once

#include <vector>

#include "rule.hpp"

namespace ft {

const std::vector<ContentRule>& builtin_content_rules();
const std::vector<PathRule>& builtin_path_rules();

}  // namespace ft
