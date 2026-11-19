/**
 * RAVEN Native — Response body normalization (Phase 12).
 *
 * Semantics-preserving normalization for comparison:
 * - Line endings: \r\n → \n
 * - Dynamic tokens: UUIDs, ISO timestamps, CSRF tokens, nonces → placeholders
 * - Truncation to MAX_NORMALIZED_BYTES
 *
 * INVARIANT: Never erases security-significant differences.
 * Python reference implementation exists in raven/response_analysis.py.
 */
#include "raven_native.h"
#include <regex>
#include <algorithm>
#include <sstream>
#include <array>

namespace raven {

// Placeholder tokens (must be stable across runs for comparable digests)
static constexpr std::string_view PH_UUID    = "{uuid}";
static constexpr std::string_view PH_TS      = "{ts}";
static constexpr std::string_view PH_CSRF    = "{csrf}";
static constexpr std::string_view PH_NONCE   = "{nonce}";

// Compiled patterns (initialized once at first call)
namespace detail {
    struct Patterns {
        std::regex uuid_re;
        std::regex ts_re;
        std::regex csrf_re;
        std::regex nonce_re;
        Patterns()
            : uuid_re(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
                      std::regex::optimize)
            , ts_re  (R"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
                      std::regex::optimize)
            , csrf_re(R"((?:csrf[_\-]?token|_token)["'\s]*[:=]["'\s]*[A-Za-z0-9+/=_\-]{8,})",
                      std::regex::optimize | std::regex::icase)
            , nonce_re(R"(nonce["'\s]*[:=]["'\s]*[A-Za-z0-9+/=_\-]{8,})",
                       std::regex::optimize | std::regex::icase)
        {}
    };
    static const Patterns& get_patterns() {
        static Patterns p;
        return p;
    }
} // namespace detail

NormalizeResult normalize_body(std::span<const uint8_t> body,
                                std::string_view content_type) noexcept {
    if (body.size() > MAX_BODY_BYTES)
        return {Status::INPUT_TOO_LARGE, {}, {}, false};

    // Only process text-like content types
    bool is_text = content_type.find("text/") != std::string_view::npos
                || content_type.find("application/json") != std::string_view::npos
                || content_type.find("application/xml") != std::string_view::npos
                || content_type.find("application/x-www-form-urlencoded") != std::string_view::npos;

    // For binary, return empty normalized (comparison uses body_digest directly)
    if (!is_text && !body.empty()) {
        // Still compute a digest for the raw body bytes
        auto hr = sha256(body);
        return {hr.status, {}, hr.hex, false};
    }

    // Safe: treat bytes as Latin-1 for normalization (no UTF-8 decode required
    // for our substitution patterns which operate on ASCII substrings)
    std::string text(reinterpret_cast<const char*>(body.data()), body.size());

    // Step 1: Normalize line endings
    {
        std::string out;
        out.reserve(text.size());
        for (size_t i = 0; i < text.size(); ++i) {
            if (text[i] == '\r') {
                out += '\n';
                if (i + 1 < text.size() && text[i + 1] == '\n')
                    ++i;
            } else {
                out += text[i];
            }
        }
        text = std::move(out);
    }

    // Step 2: Replace dynamic patterns
    try {
        const auto& p = detail::get_patterns();
        text = std::regex_replace(text, p.csrf_re,  std::string(PH_CSRF));
        text = std::regex_replace(text, p.nonce_re, std::string(PH_NONCE));
        text = std::regex_replace(text, p.uuid_re,  std::string(PH_UUID));
        text = std::regex_replace(text, p.ts_re,    std::string(PH_TS));
    } catch (...) {
        // Regex failure is non-fatal; return raw normalized (just line endings)
    }

    // Step 3: Truncate
    bool was_truncated = text.size() > MAX_NORMALIZED_BYTES;
    if (was_truncated)
        text.resize(MAX_NORMALIZED_BYTES);

    // Step 4: Compute digest of normalized text
    std::span<const uint8_t> norm_bytes(
        reinterpret_cast<const uint8_t*>(text.data()), text.size());
    auto hr = sha256(norm_bytes);
    if (hr.status != Status::OK)
        return {hr.status, {}, {}, was_truncated};

    return {Status::OK, std::move(text), std::move(hr.hex), was_truncated};
}

} // namespace raven
