/**
 * RAVEN Native — Header diff and body diff (Phases 13-14).
 *
 * Returns structural metadata only. No security verdict.
 */
#include "raven_native.h"
#include <algorithm>
#include <cstring>

namespace raven {

// ─── Header diff ─────────────────────────────────────────────────────────────

HeaderDiffResult diff_headers(
    const std::unordered_map<std::string, std::string>& a,
    const std::unordered_map<std::string, std::string>& b) noexcept {

    if (a.size() > MAX_HEADER_COUNT || b.size() > MAX_HEADER_COUNT)
        return {Status::INPUT_TOO_LARGE};

    HeaderDiffResult r{};
    r.status = Status::OK;

    for (const auto& [k, v] : a) {
        auto it = b.find(k);
        if (it == b.end()) {
            r.removed.push_back(k);
        } else if (it->second != v) {
            r.changed.push_back({k, v, it->second});
        }
    }
    for (const auto& [k, v] : b) {
        if (a.find(k) == a.end())
            r.added.push_back(k);
    }

    // Sort for deterministic output
    std::sort(r.added.begin(),   r.added.end());
    std::sort(r.removed.begin(), r.removed.end());
    std::sort(r.changed.begin(), r.changed.end(),
              [](const HeaderChange& x, const HeaderChange& y){ return x.name < y.name; });

    return r;
}

// ─── Body diff ───────────────────────────────────────────────────────────────

// Compute normalized Levenshtein similarity for short bodies (≤ 64 KB).
// For larger bodies fall back to SimHash similarity.
static double levenshtein_similarity(std::span<const uint8_t> a,
                                      std::span<const uint8_t> b) noexcept {
    constexpr size_t EXACT_LIMIT = 64 * 1024;
    if (a.size() > EXACT_LIMIT || b.size() > EXACT_LIMIT)
        return -1.0; // signal caller to use SimHash

    const size_t la = a.size(), lb = b.size();
    if (la == 0 && lb == 0) return 1.0;
    if (la == 0 || lb == 0) return 0.0;

    // dp[i][j] = edit distance between a[0..i-1] and b[0..j-1]
    // Use two-row rolling approach to save memory
    std::vector<size_t> prev(lb + 1), curr(lb + 1);
    for (size_t j = 0; j <= lb; ++j) prev[j] = j;

    for (size_t i = 1; i <= la; ++i) {
        curr[0] = i;
        for (size_t j = 1; j <= lb; ++j) {
            size_t cost = (a[i-1] == b[j-1]) ? 0 : 1;
            curr[j] = std::min({prev[j] + 1, curr[j-1] + 1, prev[j-1] + cost});
        }
        std::swap(prev, curr);
    }

    size_t edit_dist = prev[lb];
    size_t max_len   = std::max(la, lb);
    return 1.0 - static_cast<double>(edit_dist) / static_cast<double>(max_len);
}

// Count approximate changed regions (runs of differing bytes sampled at
// 4096-byte blocks)
static size_t count_changed_regions(std::span<const uint8_t> a,
                                     std::span<const uint8_t> b) noexcept {
    constexpr size_t BLOCK = 4096;
    size_t regions = 0;
    bool in_changed = false;
    size_t limit = std::min(a.size(), b.size());

    for (size_t i = 0; i < limit; i += BLOCK) {
        size_t end = std::min(i + BLOCK, limit);
        bool block_differs = (std::memcmp(a.data() + i, b.data() + i, end - i) != 0);
        if (block_differs && !in_changed) { ++regions; in_changed = true; }
        else if (!block_differs)          { in_changed = false; }
    }
    // Count tail difference in length
    if (a.size() != b.size()) ++regions;
    return regions;
}

BodyDiffResult diff_bodies(std::span<const uint8_t> a,
                            std::span<const uint8_t> b) noexcept {
    if (a.size() > MAX_BODY_BYTES || b.size() > MAX_BODY_BYTES)
        return {Status::INPUT_TOO_LARGE};

    BodyDiffResult r{};
    r.status       = Status::OK;
    r.exact_match  = (a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0);
    r.length_delta = static_cast<int64_t>(b.size()) - static_cast<int64_t>(a.size());
    r.similarity_approximate = false;

    if (r.exact_match) {
        r.normalized_match = true;
        r.similarity       = 1.0;
        r.changed_regions  = 0;
        return r;
    }

    // Normalized match: compare via normalize_body digests
    auto na = normalize_body(a, "text/plain");
    auto nb = normalize_body(b, "text/plain");
    r.normalized_match = (na.status == Status::OK && nb.status == Status::OK
                          && na.digest == nb.digest);

    r.changed_regions = count_changed_regions(a, b);

    // Similarity score
    double sim = levenshtein_similarity(a, b);
    if (sim < 0.0) {
        // Bodies too large for edit distance — use SimHash
        auto ha = simhash(a);
        auto hb = simhash(b);
        if (ha.status == Status::OK && hb.status == Status::OK) {
            r.similarity = simhash_similarity(ha.hash, hb.hash);
            r.similarity_approximate = true;
        } else {
            r.similarity = 0.0;
        }
    } else {
        r.similarity = sim;
    }

    return r;
}

} // namespace raven
