/**
 * RAVEN Native — ML feature extraction (Phase 33).
 *
 * Returns numerical features only.
 * Python makes all security decisions.
 * C++ never reads scope policy, authorization state, or credentials.
 */
#include "raven_native.h"
#include <algorithm>  // std::max_element, std::count (GCC/Clang need it explicitly)
#include <cctype>

namespace raven {

FeatureVector extract_features(
    int status_code,
    const std::unordered_map<std::string, std::string>& headers,
    std::span<const uint8_t> body,
    int64_t elapsed_ms) noexcept {

    FeatureVector f{};

    if (body.size() > MAX_BODY_BYTES) {
        f.status = Status::INPUT_TOO_LARGE;
        return f;
    }

    f.status       = Status::OK;
    f.status_code  = status_code;
    f.status_class = status_code / 100;
    f.body_size    = body.size();
    f.elapsed_ms   = elapsed_ms;

    // Header features
    f.header_count     = headers.size();
    f.has_content_type = headers.count("content-type") > 0;
    f.has_set_cookie   = headers.count("set-cookie") > 0;
    f.has_location     = headers.count("location") > 0;

    // Content type
    std::string ct;
    auto ct_it = headers.find("content-type");
    if (ct_it != headers.end()) ct = ct_it->second;

    f.is_json = ct.find("application/json") != std::string::npos;
    f.is_text_like = ct.find("text/") != std::string::npos || f.is_json;

    // Body entropy and printable ratio
    auto insp = inspect_binary(body, ct);
    if (insp.status == Status::OK) {
        f.body_entropy   = insp.entropy;
        f.printable_ratio = insp.printable_ratio;
        f.is_text_like   = insp.text_like;
    }

    // JSON structural features
    if (f.is_json && !body.empty()) {
        // Quick key count (count '"' chars / 2 as very rough approximation if
        // full parsing is too expensive; do real parse only for small bodies)
        constexpr size_t JSON_PARSE_LIMIT = 256 * 1024;
        if (body.size() <= JSON_PARSE_LIMIT) {
            // Use empty second body to count structure of 'a' side
            std::vector<uint8_t> empty_obj{'{', '}'};
            auto jd = diff_json(body, empty_obj);
            if (jd.status == Status::OK || jd.status == Status::MALFORMED) {
                f.json_key_count = jd.total_keys_a;
                // Estimate depth from diff complexity
                f.json_max_depth = static_cast<int>(
                    jd.differences.empty() ? 0 :
                    std::max_element(jd.differences.begin(), jd.differences.end(),
                        [](const JsonDiffEntry& a, const JsonDiffEntry& b){
                            return std::count(a.path.begin(), a.path.end(), '.')
                                 < std::count(b.path.begin(), b.path.end(), '.');
                        })->path.size() / 4);
            }
        }
    }

    // Similarity fields default: populated externally when baseline is available
    f.body_similarity      = -1.0;
    f.simhash_similarity   = -1.0;
    f.exact_body_match     = false;
    f.normalized_body_match = false;
    f.length_z_score       = 0.0;

    return f;
}

// Version and capability info
VersionInfo get_version() noexcept {
    return {
        NATIVE_VERSION_MAJOR, NATIVE_VERSION_MINOR, NATIVE_VERSION_PATCH,
        NATIVE_ABI_VERSION,
#ifdef _MSC_VER
        "MSVC",
#elif defined(__clang__)
        "clang",
#else
        "gcc",
#endif
#if defined(_M_X64) || defined(__x86_64__)
        "x86_64"
#elif defined(_M_ARM64) || defined(__aarch64__)
        "arm64"
#else
        "unknown"
#endif
    };
}

Capabilities get_capabilities() noexcept {
    Capabilities c{};
    c.available          = true;
    c.version            = get_version();
    c.hashing            = true;
    c.diff               = true;
    c.json_diff          = true;
    c.patterns           = true;
#if RAVEN_HAS_ZLIB
    c.compression        = true;
#else
    c.compression        = false;
#endif
    c.binary_inspection  = true;
    c.feature_extraction = true;
    c.simhash            = true;
    return c;
}

} // namespace raven
