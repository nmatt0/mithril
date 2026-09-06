// engine.hpp — the discovery engine (docs/engine-design.md).
//
// Holds the rule set and the Aho-Corasick automaton built once from every
// content-rule anchor, then scans files. One Engine is built per run and shared
// (read-only) across worker threads.
//
//   scan_content  M2 prefilter -> M3 validate/extract, over text-ish regions
//                 plus base64 / utf16le decode-then-rescan. -> content findings.
//   scan_paths    M1 path-glob rules. -> notable-file findings.
//
// M4 (format parsers for package DBs / credential stores) lives in sbom.cpp and
// is invoked by the walk directly; the CVE join is downstream and separate.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "ahocorasick.hpp"
#include "finding.hpp"
#include "reader.hpp"
#include "rule.hpp"

namespace ft {

class Engine {
public:
    Engine(std::vector<ContentRule> content, std::vector<PathRule> paths);

    // M2/M3: scan file bytes for content-rule matches.
    std::vector<Finding> scan_content(const Reader& r) const;

    // M1: match path rules against a file's relative path.
    std::vector<Finding> scan_paths(const std::string& relpath, size_t filesize) const;

private:
    void run_rules(const Reader& r, const char* enc, size_t region_off, size_t region_len,
                   size_t raw_base, std::vector<Finding>& out) const;

    std::vector<ContentRule> content_;
    std::vector<PathRule> paths_;
    AhoCorasick ac_;
    std::vector<uint32_t> id_to_rule_;  // AC pattern id -> index into content_
};

}  // namespace ft
