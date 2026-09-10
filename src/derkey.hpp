// derkey.hpp — structural scan for raw DER-encoded private keys.
//
// The content engine (engine.cpp) is text-anchored: it hunts PEM armor
// ("-----BEGIN ... PRIVATE KEY-----"), `AKIA...`, `api_key=` and the like, over
// text-ish regions only. A private key embedded in binary firmware as raw DER —
// PKCS#8 PrivateKeyInfo, PKCS#1 RSAPrivateKey, or SEC1 ECPrivateKey, with no PEM
// wrapper and no surrounding keyword — has nothing for those anchors to hit and
// lives in a region the text-ish gate skips. Such keys are invisible to the
// secrets pass yet are exactly the high-impact finding (a fleet-shared signing
// or TLS key baked into an image).
//
// This module closes that gap: it scans the whole buffer for the DER byte
// patterns that begin a private key, then *structurally parses* each candidate
// (a real ASN.1 tag/length walk, no crypto library) to confirm it is a complete,
// well-formed private key and to name its algorithm and size. Structural parsing
// — not pattern matching — is what rejects the false positives (class names, CA
// certificate stores, dictionary words) that defeat text sweeps.
#pragma once

#include <vector>

#include "finding.hpp"
#include "reader.hpp"

namespace ft {

// Scan `r` for raw DER private keys. Returns one Finding per distinct key
// (type "der-private-key", category "secret"), deduplicated so a PKCS#8 wrapper
// and the PKCS#1 key nested inside it count once. Fully offline and bounds-safe.
std::vector<Finding> scan_der_private_keys(const Reader& r);

}  // namespace ft
