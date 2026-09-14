// keycorpus.cpp — the leaked/default public-key corpus. See keycorpus.hpp.
#include "keycorpus.hpp"

#include <string_view>

namespace ft {

namespace {

// Compiled in from the vendored public keys under data/keycorpus/ via
// tools/gen_keycorpus.py. Baked into the binary (no runtime table, no network);
// the generator runs only at authoring time so the corpus is reproducible and
// auditable from source. Keyed by fp_ssh and fp_modn (see keycorpus.hpp).
#include "keycorpus_corpus.inc"

}  // namespace

const KnownLeakedKey* known_leaked_key(const std::string& fp) {
    for (const auto& k : kLeakedKeys)
        if (fp == k.fp) return &k;
    return nullptr;
}

size_t leaked_key_corpus_size() { return sizeof(kLeakedKeys) / sizeof(kLeakedKeys[0]); }

}  // namespace ft
