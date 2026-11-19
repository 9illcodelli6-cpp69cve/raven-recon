/**
 * RAVEN Native — SimHash for approximate textual similarity (Phase 16).
 *
 * 64-bit SimHash: tokenize input into N-grams, hash each token with FNV-1a,
 * accumulate bit-level weighted vote, return fingerprint.
 *
 * Similarity = 1 - hamming_distance(a, b) / 64.
 * Treat as metadata only — not a security verdict.
 */
#include "raven_native.h"
#include <cstring>

namespace raven {

// FNV-1a 64-bit
static uint64_t fnv1a_64(const uint8_t* data, size_t len) noexcept {
    uint64_t h = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < len; ++i) {
        h ^= static_cast<uint64_t>(data[i]);
        h *= UINT64_C(1099511628211);
    }
    return h;
}

SimHashResult simhash(std::span<const uint8_t> data) noexcept {
    if (data.size() > MAX_BODY_BYTES)
        return {Status::INPUT_TOO_LARGE};

    if (data.empty())
        return {Status::OK, 0, 0.0};

    // 4-gram shingles, stride 2
    constexpr size_t N = 4;
    constexpr size_t STRIDE = 2;

    int64_t v[64] = {};  // bit-level vote counters

    size_t limit = data.size() >= N ? data.size() - N + 1 : 0;
    for (size_t i = 0; i < limit; i += STRIDE) {
        uint64_t h = fnv1a_64(data.data() + i, N);
        for (int b = 0; b < 64; ++b)
            v[b] += ((h >> b) & 1) ? 1 : -1;
    }

    uint64_t fp = 0;
    for (int b = 0; b < 64; ++b)
        if (v[b] > 0) fp |= (UINT64_C(1) << b);

    return {Status::OK, fp, 0.0};
}

double simhash_similarity(uint64_t a, uint64_t b) noexcept {
    uint64_t diff = a ^ b;
    // popcount of diff = hamming distance
#ifdef _MSC_VER
    int hd = static_cast<int>(__popcnt64(diff));
#else
    int hd = __builtin_popcountll(diff);
#endif
    return 1.0 - static_cast<double>(hd) / 64.0;
}

} // namespace raven
