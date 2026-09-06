// json.hpp — hand-rolled JSON emit for a mithril Report (zero deps for v0,
// mirroring moria). The default, machine/LLM-facing output (`-j`/`--json`).
#pragma once

#include <string>

#include "report.hpp"

namespace ft {

// Serialize a whole scan Report as one JSON object (schema_version, root,
// counts, a one-line summary, and a per-category findings array).
std::string emit_report_json(const Report& rep, const Passes& passes);

}  // namespace ft
