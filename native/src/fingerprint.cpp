/**
 * RAVEN Native — Versioned response fingerprints (Phase 21).
 *
 * Fingerprint v1: status + selected headers + body digest + size + content_type
 * The fingerprint schema is versioned; Python rejects unknown fp_version.
 */
#include "raven_native.h"
#include <sstream>
#include <algorithm>

namespace raven {

static constexpr uint32_t FP_VERSION = 1;

// Headers that contribute to fingerprint identity
static constexpr std::array<std::string_view, 5> FP_HEADERS = {
    "content-type", "x-frame-options", "x-content-type-options",
    "cache-control", "x-powered-by"
};

ResponseFingerprint compute_fingerprint(
    int status_code,
    const std::unordered_map<std::string, std::string>& headers,
    std::span<const uint8_t> body) noexcept {

    if (body.size() > MAX_BODY_BYTES)
        return {Status::INPUT_TOO_LARGE};

    auto hr = sha256(body);
    if (hr.status != Status::OK)
        return {hr.status};

    std::string ct;
    {
        auto it = headers.find("content-type");
        if (it != headers.end()) ct = it->second;
        // strip parameters
        auto pos = ct.find(';');
        if (pos != std::string::npos) ct.resize(pos);
        for (char& c : ct) c = static_cast<char>(std::tolower(static_cast<uint8_t>(c)));
    }

    // Build composite fingerprint input
    std::ostringstream ss;
    ss << "v" << FP_VERSION << "|" << status_code << "|" << ct << "|" << hr.hex;
    for (auto h : FP_HEADERS) {
        std::string key(h);
        auto it = headers.find(key);
        ss << "|" << h << ":" << (it != headers.end() ? it->second : "");
    }

    std::string fp_input = ss.str();
    std::span<const uint8_t> fp_bytes(
        reinterpret_cast<const uint8_t*>(fp_input.data()), fp_input.size());
    auto fp_hash = sha256(fp_bytes);

    ResponseFingerprint r{};
    r.status         = Status::OK;
    r.fp_version     = FP_VERSION;
    r.status_code    = status_code;
    r.body_digest    = hr.hex;
    r.content_type   = ct;
    r.body_size      = body.size();
    r.fingerprint_id = fp_hash.hex;

    return r;
}

} // namespace raven
