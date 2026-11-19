/**
 * RAVEN Native — Multi-pattern scanner: Aho-Corasick (Phase 22).
 *
 * Deterministic, linear-time O(text + matches) pattern matching.
 * No external callbacks. No network. Pattern hits are indicators only.
 *
 * Patterns are fixed at construction; the automaton is immutable and
 * thread-safe after build.
 */
#include "raven_native.h"
#include <queue>
#include <cassert>

namespace raven {

// ─── Aho-Corasick automaton ───────────────────────────────────────────────────

struct PatternScanner::Impl {
    struct Node {
        std::array<int32_t, 256> next{};
        int32_t fail    = 0;
        int32_t output  = -1;  // pattern id if this is a terminal (or linked via output links)
        std::vector<uint32_t> outputs;
        Node() { next.fill(-1); }
    };

    std::vector<Node>    nodes;
    std::vector<size_t>  pattern_lengths;
    bool built = false;

    void build(const std::vector<std::string>& patterns) {
        nodes.emplace_back();  // root node = 0

        // Insert patterns into trie
        for (size_t pid = 0; pid < patterns.size(); ++pid) {
            const std::string& pat = patterns[pid];
            int32_t cur = 0;
            for (uint8_t c : pat) {
                if (nodes[cur].next[c] == -1) {
                    nodes[cur].next[c] = static_cast<int32_t>(nodes.size());
                    nodes.emplace_back();
                }
                cur = nodes[cur].next[c];
            }
            nodes[cur].outputs.push_back(static_cast<uint32_t>(pid));
            pattern_lengths.push_back(pat.size());
        }

        // BFS to build failure links
        std::queue<int32_t> q;
        for (int32_t c = 0; c < 256; ++c) {
            int32_t s = nodes[0].next[c];
            if (s == -1) {
                nodes[0].next[c] = 0;
            } else {
                nodes[s].fail = 0;
                q.push(s);
            }
        }

        while (!q.empty()) {
            int32_t r = q.front(); q.pop();
            // Merge outputs from fail-link chain
            int32_t f = nodes[r].fail;
            for (uint32_t pid : nodes[f].outputs)
                nodes[r].outputs.push_back(pid);

            for (int32_t c = 0; c < 256; ++c) {
                int32_t s = nodes[r].next[c];
                if (s == -1) {
                    nodes[r].next[c] = nodes[nodes[r].fail].next[c];
                } else {
                    nodes[s].fail = nodes[nodes[r].fail].next[c];
                    q.push(s);
                }
            }
        }

        built = true;
    }
};

// RAII destructor must be defined where Impl is complete
PatternScanner::~PatternScanner() = default;
PatternScanner::PatternScanner(PatternScanner&&) noexcept = default;
PatternScanner& PatternScanner::operator=(PatternScanner&&) noexcept = default;
PatternScanner::PatternScanner(std::unique_ptr<Impl> impl, size_t n)
    : impl_(std::move(impl)), pattern_count_(n) {}

std::optional<PatternScanner> PatternScanner::build(
    const std::vector<std::string>& patterns) noexcept {
    if (patterns.size() > MAX_PATTERN_COUNT)
        return std::nullopt;

    try {
        auto impl = std::make_unique<Impl>();
        impl->build(patterns);
        size_t n = patterns.size();
        return PatternScanner(std::move(impl), n);
    } catch (...) {
        return std::nullopt;
    }
}

ScanResult PatternScanner::scan(std::span<const uint8_t> data) const noexcept {
    constexpr size_t MAX_MATCHES = 65536;

    if (!impl_ || !impl_->built)
        return {Status::INTERNAL_ERROR};
    if (data.size() > MAX_BODY_BYTES)
        return {Status::INPUT_TOO_LARGE};

    ScanResult r{};
    r.status = Status::OK;

    int32_t state = 0;
    for (size_t i = 0; i < data.size(); ++i) {
        uint8_t c = data[i];
        state = impl_->nodes[state].next[c];

        for (uint32_t pid : impl_->nodes[state].outputs) {
            if (r.matches.size() >= MAX_MATCHES) {
                r.truncated = true;
                return r;
            }
            size_t plen = impl_->pattern_lengths[pid];
            size_t offset = i + 1 >= plen ? i + 1 - plen : 0;
            r.matches.push_back({offset, plen, pid});
        }
    }

    return r;
}

} // namespace raven
