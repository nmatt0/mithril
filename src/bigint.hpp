// bigint.hpp — a minimal, in-tree big unsigned integer.
//
// mithril links no third-party libraries and builds its own crypto primitives
// (SHA-256, CRC32, DEFLATE); this is the same choice for the multiprecision
// arithmetic the Phase-2 key-weakness checks need (Fermat close primes,
// batch-GCD shared primes, Wiener small-d). It implements only the operations
// those checks use — no general-purpose bignum. Non-negative integers only.
//
// Representation: base 2^32 limbs, little-endian (limb[0] is least significant),
// always normalized (no high zero limbs; zero is the empty vector). Every op is
// bounds-checked and allocation-guarded; division by zero yields zero (the
// callers never divide by zero, but the guard keeps a hostile modulus safe).
#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace ft {

class BigUint {
public:
    BigUint() = default;
    explicit BigUint(uint64_t v);

    // Big-endian bytes in / out (leading zeros ignored / not emitted).
    static BigUint from_be(std::span<const uint8_t> be);
    std::vector<uint8_t> to_be() const;

    bool is_zero() const { return limbs_.empty(); }
    bool is_odd() const { return !limbs_.empty() && (limbs_[0] & 1u); }
    size_t bit_length() const;
    uint64_t low64() const;  // low 64 bits (for small comparisons/printing)

    // Comparison: <0, 0, >0.
    static int cmp(const BigUint& a, const BigUint& b);
    bool operator==(const BigUint& o) const { return cmp(*this, o) == 0; }
    bool operator!=(const BigUint& o) const { return cmp(*this, o) != 0; }
    bool operator<(const BigUint& o) const { return cmp(*this, o) < 0; }
    bool operator<=(const BigUint& o) const { return cmp(*this, o) <= 0; }
    bool operator>(const BigUint& o) const { return cmp(*this, o) > 0; }
    bool operator>=(const BigUint& o) const { return cmp(*this, o) >= 0; }

    BigUint operator+(const BigUint& o) const;
    BigUint operator-(const BigUint& o) const;  // saturates at 0 if o > *this
    BigUint operator*(const BigUint& o) const;
    BigUint operator%(const BigUint& o) const;

    // q = *this / d, r = *this % d (bit-by-bit long division). d==0 -> q=r=0.
    void divmod(const BigUint& d, BigUint& q, BigUint& r) const;

    BigUint shl_bits(size_t n) const;
    BigUint shr_bits(size_t n) const;

    static BigUint gcd(BigUint a, BigUint b);

    // Floor integer square root.
    BigUint isqrt() const;
    // True if *this is a perfect square; if so and `root` != nullptr, sets *root.
    bool is_perfect_square(BigUint* root = nullptr) const;

private:
    std::vector<uint32_t> limbs_;  // little-endian, normalized
    void normalize();
    void set_bit(size_t i);
    bool test_bit(size_t i) const;
};

}  // namespace ft
