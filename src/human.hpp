// human.hpp — human-readable ("pretty") rendering of a mithril Report.
//
// JSON (json.hpp) stays the default, machine-facing output. This renderer
// produces a compact, aligned, optionally-colored text view for a person at a
// terminal: a one-line summary, an aligned findings table, then a plain footer
// (run stats) after a blank line. Mirrors moria's human output style.
#pragma once

#include <string>

#include "report.hpp"

namespace ft {

std::string emit_report_human(const Report& rep, const Passes& passes, const std::string& footer,
                              bool color);

}  // namespace ft
