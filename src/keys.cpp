// keys.cpp — Key Weakness pass. See keys.hpp.
#include "keys.hpp"

#include <unordered_set>

#include "ecc.hpp"
#include "keycorpus.hpp"
#include "keyweak.hpp"
#include "pubkey.hpp"

namespace ft {

namespace {

// Upper bound for the EC small-scalar search per key. The observed real-world
// failure (eMudhra, Oct 2026) produced <= 8-bit scalars; 2^12 is a ~17x margin
// over that. A scalar needs ~2^128 for any security, so this reaches only the
// "broken RNG" floor; extending the reach cheaply (baby-step/giant-step is
// O(sqrt(limit))) is future work.
constexpr uint64_t kEcSmallScalarLimit = 1u << 12;

// A healthy EC key's search walks the full range (a miss), so a file holding many
// EC certs (a bundled CA trust store) could spend time proving negatives. The
// budget below covers a normal trust store (~50 keys) at full reach; once spent,
// later keys fall back to the floor, which still covers the known class (eMudhra
// max scalar 237, so 512 keeps a >2x margin for every key in the file). This
// bounds a pathological many-EC-cert file instead of letting it run unbounded.
constexpr uint64_t kEcFileStepBudget = 200000;
constexpr uint64_t kEcMinScan = 512;

size_t bit_width_u64(uint64_t v) {
    size_t b = 0;
    while (v) { ++b; v >>= 1; }
    return b;
}

// A keys finding. `sev` is [high]/[medium]/[info] (risk); `tier` is the parse/match
// confidence (a corpus fingerprint match or ROCA fingerprint is exact -> Validated;
// a size/exponent heuristic is Structural).
Finding mk(const char* type, const char* sev, Confidence tier, std::string label,
           std::string why, std::string desc, size_t off) {
    Finding f;
    f.type = type;
    f.category = "keys";
    f.offset = off;
    f.label = std::move(label);
    f.description = std::move(desc);
    f.set_confidence(tier, std::string("[") + sev + "] " + std::move(why));
    return f;
}

}  // namespace

std::vector<Finding> scan_keys(const std::string& path, std::span<const uint8_t> data,
                               std::vector<RsaKeyInfo>* out_rsa) {
    (void)path;
    std::vector<Finding> out;
    auto keys = extract_public_keys(data);
    if (keys.empty()) return out;

    // Dedup keys within the file (a cert matched as PEM and again as whole-file
    // DER, or the same host key in two files' worth of one buffer).
    std::unordered_set<std::string> seen;

    uint64_t ec_budget = kEcFileStepBudget;  // shared EC search budget for this file

    for (const auto& k : keys) {
        std::string ident = k.fp_ssh + "|" + k.fp_der + "|" + k.fp_modn;
        if (!seen.insert(ident).second) continue;

        const std::string& kind = k.label;  // e.g. "RSA-2048 ssh-public-key"

        // 1. Disclosure: the private half is public (leaked/default/hardcoded).
        //    Match on any fingerprint namespace the key exposes.
        const KnownLeakedKey* leak = nullptr;
        for (const std::string* fp : {&k.fp_ssh, &k.fp_modn, &k.fp_der}) {
            if (!fp->empty()) {
                if (const KnownLeakedKey* m = known_leaked_key(*fp)) { leak = m; break; }
            }
        }
        if (leak) {
            std::string why = std::string(leak->label) + " — private key is public (" +
                              leak->ref + ")";
            std::string impact =
                std::string(leak->key_use) == "host"
                    ? "an attacker can impersonate/MITM this host (host key)"
                    : (std::string(leak->key_use) == "authorized"
                           ? "an attacker can log in with the public-domain private key"
                           : "the matching private key is publicly available");
            out.push_back(mk("leaked-key", "high", Confidence::Validated, leak->label,
                             std::move(why), impact, k.offset));
        }

        // 2. ROCA (CVE-2017-15361): RSA modulus carries the Infineon fingerprint.
        if (k.algo == "RSA" && is_roca(k.n)) {
            out.push_back(mk("roca-key", "high", Confidence::Validated, kind,
                             "RSA key carries the ROCA fingerprint (CVE-2017-15361): the "
                             "private key is recoverable from the public modulus",
                             "Infineon RSALib structured primes; Coppersmith-factorable",
                             k.offset));
        }

        // 3. Structural weaknesses (RSA size/exponent), computable from the key.
        if (k.algo == "RSA") {
            for (const auto& w : rsa_structural_weaknesses(k.bits, k.e_be, k.n)) {
                out.push_back(mk(w.id.c_str(), w.sev.c_str(), Confidence::Structural, kind,
                                 w.why, w.cwe, k.offset));
            }

            // The factoring checks below are superlinear in the modulus size; cap
            // it so a hostile oversized modulus cannot turn a scan into a DoS.
            // Real RSA moduli are <= 16384 bits.
            const bool factor_ok = k.bits >= 256 && k.bits <= 16384;

            // 4. Fermat close primes: recover p,q when |p-q| is small (bad RNG /
            //    shared-high-bits generation). A hit is proof — we have the factors.
            std::vector<uint8_t> p, q;
            if (factor_ok && fermat_factor(k.n, p, q)) {
                out.push_back(mk("fermat-factorable", "high", Confidence::Validated, kind,
                                 "RSA modulus factored by Fermat's method (close primes): the "
                                 "private key is recovered",
                                 "CWE-326 (close-prime generation; |p-q| small)", k.offset));
            }

            // 5. Wiener small private exponent: only meaningful when e is large
            //    relative to n (a small e like 65537 is never Wiener-vulnerable),
            //    so skip the CF work otherwise. e bit-length from the full bytes.
            size_t e_bits = k.e_be.empty() ? 0 : (k.e_be.size() - 1) * 8 + bit_width_u64(k.e_be[0]);
            if (factor_ok && e_bits && e_bits * 2 > k.bits) {
                std::vector<uint8_t> d;
                if (wiener_attack(k.n, k.e_be, d)) {
                    out.push_back(mk("wiener-weak", "high", Confidence::Validated, kind,
                                     "small RSA private exponent recovered by Wiener's attack "
                                     "(continued-fraction) from the public key",
                                     "CWE-326 (private exponent too small)", k.offset));
                }
            }

            if (out_rsa) out_rsa->push_back(RsaKeyInfo{k.offset, k.n, k.e, k.bits});
        }

        // 5b. DSA domain-parameter size. The security of DSA rests on the prime
        //     p (the discrete-log modulus); below the 2048-bit floor it is
        //     deprecated, and <1024 is broken. Reported under a DSA-specific type
        //     so a DSA key is never mislabeled as RSA (GH #44).
        if (k.algo == "DSA" && k.bits > 0 && k.bits < 2048) {
            out.push_back(mk("dsa-weak-parameters", k.bits < 1024 ? "high" : "medium",
                             Confidence::Structural, kind,
                             "DSA prime p is " + std::to_string(k.bits) +
                                 " bits: below the 2048-bit floor (deprecated)",
                             "CWE-326", k.offset));
        }

        // 6. EC small-scalar: a public point Q = d*G for a catastrophically small
        //    private scalar d (broken RNG / near-zero key generation — the Oct 2026
        //    eMudhra intermediate-CA compromise, P-384 scalars 4..237). A bounded
        //    search recovers d; a legitimate scalar is astronomically larger than
        //    the bound, so a hit is proof of a recoverable private key.
        if (k.algo == "EC" && !k.ec_x.empty() && !k.ec_y.empty()) {
            const EcCurve* c = ec_curve_by_name(k.curve);
            // Only a well-formed affine point (coordinates exactly the field size)
            // is analyzed; this also bounds the field arithmetic (a malformed
            // oversized coordinate never reaches the reducer).
            if (c && k.ec_x.size() <= c->field_bytes && k.ec_y.size() <= c->field_bytes) {
                uint64_t lim = ec_budget >= kEcSmallScalarLimit ? kEcSmallScalarLimit
                               : (ec_budget > kEcMinScan ? ec_budget : kEcMinScan);
                ec_budget -= (ec_budget > lim) ? lim : ec_budget;
                uint64_t d = 0;
                if (ec_recover_small_scalar(*c, k.ec_x, k.ec_y, lim, d)) {
                    out.push_back(mk("ec-small-scalar", "high", Confidence::Validated, kind,
                                     "EC private scalar recovered by small-scalar search: d=" +
                                         std::to_string(d) + " on " + c->name +
                                         " (a real private key is ~" + std::to_string(k.bits) +
                                         "-bit); the private key is trivially recoverable",
                                     "CWE-320 (weak key generation; near-zero EC private scalar)",
                                     k.offset));
                }
            }
        }
    }
    return out;
}

}  // namespace ft
