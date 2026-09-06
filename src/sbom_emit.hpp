// sbom_emit.hpp — standard-format SBOM emitters (thin adapters over Components).
//
// Both are hand-emitted (zero-dep, like moria's JSON). CycloneDX 1.5 is the
// interop/tooling format (native input to the Phase 3 CVE join); SPDX 2.3 rides
// along for compliance/provenance. The internal Component model (component.hpp)
// stays format-neutral; these just serialize it two ways.
#pragma once

#include <string>
#include <vector>

#include "component.hpp"

namespace ft {

std::string emit_cyclonedx(const std::vector<Component>& components, const std::string& tool_version);
std::string emit_spdx(const std::vector<Component>& components, const std::string& tool_version);

}  // namespace ft
