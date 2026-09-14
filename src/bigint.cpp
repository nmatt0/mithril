// bigint.cpp — minimal in-tree big unsigned integer. See bigint.hpp.
#include "bigint.hpp"

#include <algorithm>

namespace ft {

void BigUint::normalize() {
    while (!limbs_.empty() && limbs_.back() == 0) limbs_.pop_back();
}

BigUint::BigUint(uint64_t v) {
    if (v & 0xFFFFFFFFull) limbs_.push_back(uint32_t(v & 0xFFFFFFFFull));
    else if (v) limbs_.push_back(0);
    if (v >> 32) limbs_.push_back(uint32_t(v >> 32));
    normalize();
}

BigUint BigUint::from_be(std::span<const uint8_t> be) {
    // Skip leading zero bytes, then pack 4 bytes per limb from the least
    // significant end.
    size_t s = 0;
    while (s < be.size() && be[s] == 0) ++s;
    BigUint r;
    size_t n = be.size() - s;
    r.limbs_.assign((n + 3) / 4, 0);
    for (size_t i = 0; i < n; ++i) {
        uint8_t byte = be[be.size() - 1 - i];  // i-th least significant byte
        r.limbs_[i / 4] |= uint32_t(byte) << (8 * (i % 4));
    }
    r.normalize();
    return r;
}

std::vector<uint8_t> BigUint::to_be() const {
    if (limbs_.empty()) return {};
    std::vector<uint8_t> out;
    out.reserve(limbs_.size() * 4);
    for (size_t i = limbs_.size(); i-- > 0;) {
        out.push_back(uint8_t(limbs_[i] >> 24));
        out.push_back(uint8_t(limbs_[i] >> 16));
        out.push_back(uint8_t(limbs_[i] >> 8));
        out.push_back(uint8_t(limbs_[i]));
    }
    size_t z = 0;
    while (z + 1 < out.size() && out[z] == 0) ++z;  // strip leading zero bytes
    return std::vector<uint8_t>(out.begin() + z, out.end());
}

size_t BigUint::bit_length() const {
    if (limbs_.empty()) return 0;
    size_t bits = (limbs_.size() - 1) * 32;
    uint32_t top = limbs_.back();
    while (top) { ++bits; top >>= 1; }
    return bits;
}

uint64_t BigUint::low64() const {
    uint64_t v = limbs_.empty() ? 0 : limbs_[0];
    if (limbs_.size() > 1) v |= uint64_t(limbs_[1]) << 32;
    return v;
}

bool BigUint::test_bit(size_t i) const {
    size_t limb = i / 32;
    if (limb >= limbs_.size()) return false;
    return (limbs_[limb] >> (i % 32)) & 1u;
}

void BigUint::set_bit(size_t i) {
    size_t limb = i / 32;
    if (limb >= limbs_.size()) limbs_.resize(limb + 1, 0);
    limbs_[limb] |= uint32_t(1) << (i % 32);
}

int BigUint::cmp(const BigUint& a, const BigUint& b) {
    if (a.limbs_.size() != b.limbs_.size())
        return a.limbs_.size() < b.limbs_.size() ? -1 : 1;
    for (size_t i = a.limbs_.size(); i-- > 0;)
        if (a.limbs_[i] != b.limbs_[i]) return a.limbs_[i] < b.limbs_[i] ? -1 : 1;
    return 0;
}

BigUint BigUint::operator+(const BigUint& o) const {
    BigUint r;
    size_t n = std::max(limbs_.size(), o.limbs_.size());
    r.limbs_.assign(n, 0);
    uint64_t carry = 0;
    for (size_t i = 0; i < n; ++i) {
        uint64_t s = carry;
        if (i < limbs_.size()) s += limbs_[i];
        if (i < o.limbs_.size()) s += o.limbs_[i];
        r.limbs_[i] = uint32_t(s & 0xFFFFFFFFull);
        carry = s >> 32;
    }
    if (carry) r.limbs_.push_back(uint32_t(carry));
    r.normalize();
    return r;
}

BigUint BigUint::operator-(const BigUint& o) const {
    if (cmp(*this, o) <= 0) return BigUint();  // saturate at zero
    BigUint r;
    r.limbs_.assign(limbs_.size(), 0);
    int64_t borrow = 0;
    for (size_t i = 0; i < limbs_.size(); ++i) {
        int64_t s = int64_t(limbs_[i]) - borrow - (i < o.limbs_.size() ? int64_t(o.limbs_[i]) : 0);
        if (s < 0) { s += (int64_t(1) << 32); borrow = 1; }
        else borrow = 0;
        r.limbs_[i] = uint32_t(s);
    }
    r.normalize();
    return r;
}

BigUint BigUint::operator*(const BigUint& o) const {
    if (limbs_.empty() || o.limbs_.empty()) return BigUint();
    BigUint r;
    r.limbs_.assign(limbs_.size() + o.limbs_.size(), 0);
    for (size_t i = 0; i < limbs_.size(); ++i) {
        uint64_t carry = 0;
        uint64_t a = limbs_[i];
        for (size_t j = 0; j < o.limbs_.size(); ++j) {
            uint64_t cur = uint64_t(r.limbs_[i + j]) + a * o.limbs_[j] + carry;
            r.limbs_[i + j] = uint32_t(cur & 0xFFFFFFFFull);
            carry = cur >> 32;
        }
        r.limbs_[i + o.limbs_.size()] += uint32_t(carry);
    }
    r.normalize();
    return r;
}

BigUint BigUint::shl_bits(size_t n) const {
    if (limbs_.empty()) return BigUint();
    BigUint r;
    size_t words = n / 32, bits = n % 32;
    r.limbs_.assign(limbs_.size() + words + 1, 0);
    for (size_t i = 0; i < limbs_.size(); ++i) {
        uint64_t v = uint64_t(limbs_[i]) << bits;
        r.limbs_[i + words] |= uint32_t(v & 0xFFFFFFFFull);
        r.limbs_[i + words + 1] |= uint32_t(v >> 32);
    }
    r.normalize();
    return r;
}

BigUint BigUint::shr_bits(size_t n) const {
    size_t words = n / 32, bits = n % 32;
    if (words >= limbs_.size()) return BigUint();
    BigUint r;
    r.limbs_.assign(limbs_.size() - words, 0);
    for (size_t i = 0; i < r.limbs_.size(); ++i) {
        uint64_t v = limbs_[i + words] >> bits;
        if (bits && i + words + 1 < limbs_.size())
            v |= uint64_t(limbs_[i + words + 1]) << (32 - bits);
        r.limbs_[i] = uint32_t(v & 0xFFFFFFFFull);
    }
    r.normalize();
    return r;
}

void BigUint::divmod(const BigUint& d, BigUint& q, BigUint& r) const {
    q = BigUint();
    r = BigUint();
    if (d.is_zero()) return;  // guard; callers never divide by zero
    if (cmp(*this, d) < 0) { r = *this; return; }
    // Bit-by-bit long division, most significant bit first.
    size_t nbits = bit_length();
    q.limbs_.assign((nbits + 31) / 32, 0);
    for (size_t i = nbits; i-- > 0;) {
        r = r.shl_bits(1);
        if (test_bit(i)) r.set_bit(0);
        if (cmp(r, d) >= 0) {
            r = r - d;
            q.set_bit(i);
        }
    }
    q.normalize();
    r.normalize();
}

BigUint BigUint::operator%(const BigUint& o) const {
    BigUint q, r;
    divmod(o, q, r);
    return r;
}

BigUint BigUint::gcd(BigUint a, BigUint b) {
    while (!b.is_zero()) {
        BigUint r = a % b;
        a = b;
        b = r;
    }
    return a;
}

BigUint BigUint::isqrt() const {
    if (is_zero()) return BigUint();
    // Digit-by-digit (base-2) integer square root: no multiply, no divide.
    // Largest power of four <= *this.
    size_t nb = bit_length();
    BigUint bit;
    bit.set_bit((nb - 1) & ~size_t(1));  // 1 << (2*floor((nb-1)/2))
    BigUint num = *this, res;
    while (!bit.is_zero()) {
        BigUint rb = res + bit;
        if (cmp(num, rb) >= 0) {
            num = num - rb;
            res = res.shr_bits(1) + bit;
        } else {
            res = res.shr_bits(1);
        }
        bit = bit.shr_bits(2);
    }
    return res;
}

bool BigUint::is_perfect_square(BigUint* root) const {
    BigUint s = isqrt();
    if (s * s == *this) {
        if (root) *root = s;
        return true;
    }
    return false;
}

}  // namespace ft
