#include "version.hpp"

#include <cctype>
#include <string>
#include <string_view>

namespace ft {

namespace {

// dpkg's character ordering: '~' before everything (incl. end of string),
// then letters, then non-letters. Digits are handled separately.
int order(unsigned char c) {
    if (std::isdigit(c)) return 0;
    if (std::isalpha(c)) return c;
    if (c == '~') return -1;
    if (c) return static_cast<int>(c) + 256;
    return 0;  // end of string
}

// dpkg verrevcmp over two version fragments (upstream or revision).
int verrevcmp(std::string_view a, std::string_view b) {
    size_t i = 0, j = 0;
    while (i < a.size() || j < b.size()) {
        int first_diff = 0;
        // Compare the non-digit run.
        while ((i < a.size() && !std::isdigit((unsigned char)a[i])) ||
               (j < b.size() && !std::isdigit((unsigned char)b[j]))) {
            int ac = i < a.size() ? order((unsigned char)a[i]) : 0;
            int bc = j < b.size() ? order((unsigned char)b[j]) : 0;
            if (ac != bc) return ac - bc;
            ++i;
            ++j;
        }
        // Skip leading zeros in the digit run.
        while (i < a.size() && a[i] == '0') ++i;
        while (j < b.size() && b[j] == '0') ++j;
        // Compare the digit run: longer number wins; else first differing digit.
        while (i < a.size() && std::isdigit((unsigned char)a[i]) && j < b.size() &&
               std::isdigit((unsigned char)b[j])) {
            if (!first_diff) first_diff = a[i] - b[j];
            ++i;
            ++j;
        }
        if (i < a.size() && std::isdigit((unsigned char)a[i])) return 1;
        if (j < b.size() && std::isdigit((unsigned char)b[j])) return -1;
        if (first_diff) return first_diff;
    }
    return 0;
}

int sign(int x) { return x < 0 ? -1 : (x > 0 ? 1 : 0); }

}  // namespace

int deb_vercmp(const std::string& A, const std::string& B) {
    std::string_view a = A, b = B;

    // Epoch: leading digits before a ':'. Default 0.
    auto split_epoch = [](std::string_view v) -> std::pair<long, std::string_view> {
        size_t colon = v.find(':');
        if (colon != std::string_view::npos) {
            bool alldig = colon > 0;
            for (size_t k = 0; k < colon; ++k)
                if (!std::isdigit((unsigned char)v[k])) alldig = false;
            if (alldig) {
                long e = 0;
                for (size_t k = 0; k < colon; ++k) e = e * 10 + (v[k] - '0');
                return {e, v.substr(colon + 1)};
            }
        }
        return {0, v};
    };
    // Revision: everything after the last '-'. Upstream is the rest.
    auto split_rev = [](std::string_view v) -> std::pair<std::string_view, std::string_view> {
        size_t dash = v.rfind('-');
        if (dash == std::string_view::npos) return {v, std::string_view()};
        return {v.substr(0, dash), v.substr(dash + 1)};
    };

    auto [ea, ra] = split_epoch(a);
    auto [eb, rb] = split_epoch(b);
    if (ea != eb) return ea < eb ? -1 : 1;

    auto [up_a, rev_a] = split_rev(ra);
    auto [up_b, rev_b] = split_rev(rb);

    int r = verrevcmp(up_a, up_b);
    if (r) return sign(r);
    return sign(verrevcmp(rev_a, rev_b));
}

}  // namespace ft
