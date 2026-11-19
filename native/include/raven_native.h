/**
 * RAVEN Native Analysis Engine — Public C++ API
 *
 * SECURITY NOTE: All inputs from HTTP responses are HOSTILE TARGET-CONTROLLED DATA.
 * Every parsing function enforces explicit resource limits and returns structured
 * results. No C++ exception crosses the ABI boundary — all errors use return codes.
 *
 * This library is compute-only. It has NO network access, NO file I/O beyond
 * what callers explicitly pass in, and NO security policy authority.
 */
#pragma once

#include <array>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <unordered_map>
#include <span>

namespace raven {

// ─── ABI versioning ──────────────────────────────────────────────────────────

static constexpr uint32_t NATIVE_VERSION_MAJOR = 6;
static constexpr uint32_t NATIVE_VERSION_MINOR = 0;
static constexpr uint32_t NATIVE_VERSION_PATCH = 0;
static constexpr uint32_t NATIVE_ABI_VERSION   = 1;

struct VersionInfo {
    uint32_t major_ver;
    uint32_t minor_ver;
    uint32_t patch_ver;
    uint32_t abi_version;
    const char* compiler_id;    // "MSVC", "clang", "gcc"
    const char* arch;           // "x86_64", "arm64"
};

VersionInfo get_version() noexcept;

// ─── Resource limits ─────────────────────────────────────────────────────────

static constexpr size_t MAX_BODY_BYTES        = 10 * 1024 * 1024;   // 10 MB
static constexpr size_t MAX_NORMALIZED_BYTES  =  8 * 1024;           // 8 KB
static constexpr size_t MAX_HEADER_COUNT      = 512;
static constexpr size_t MAX_JSON_DEPTH        = 64;
static constexpr size_t MAX_JSON_KEYS         = 4096;
static constexpr size_t MAX_PATTERN_COUNT     = 16384;
static constexpr size_t MAX_GZIP_EXPAND_RATIO = 128;
static constexpr size_t MAX_GZIP_OUTPUT_BYTES = 50 * 1024 * 1024;  // 50 MB

// ─── Common result codes ──────────────────────────────────────────────────────

enum class Status : int32_t {
    OK              =  0,
    INPUT_TOO_LARGE = -1,
    INVALID_INPUT   = -2,
    LIMIT_REACHED   = -3,
    TRUNCATED       = -4,
    MALFORMED       = -5,
    UNSUPPORTED     = -6,
    INTERNAL_ERROR  = -99,
};

// ─── Normalization (Phase 12) ─────────────────────────────────────────────────

struct NormalizeResult {
    Status status;
    std::string normalized;   // semantics-preserving normalized text (≤ MAX_NORMALIZED_BYTES)
    std::string digest;       // SHA-256 hex of normalized text
    bool was_truncated;
};

/**
 * Normalize response body bytes for comparison.
 * Strips volatile artifacts (line endings, known nonces, timestamps) without
 * erasing security-significant differences.
 *
 * INPUT: raw response body bytes (may contain embedded nulls, arbitrary encoding)
 * LIMITS: truncates at MAX_NORMALIZED_BYTES; enforces MAX_BODY_BYTES input limit
 */
NormalizeResult normalize_body(std::span<const uint8_t> body,
                                std::string_view content_type) noexcept;

// ─── Header diff (Phase 13) ───────────────────────────────────────────────────

struct HeaderChange {
    std::string name;
    std::string old_value;   // empty if added
    std::string new_value;   // empty if removed
};

struct HeaderDiffResult {
    Status status;
    std::vector<std::string>   added;    // header names present in b, absent in a
    std::vector<std::string>   removed;  // header names present in a, absent in b
    std::vector<HeaderChange>  changed;
};

/**
 * Compute header differences between two responses.
 * Returns structural diff only — no security verdict.
 */
HeaderDiffResult diff_headers(
    const std::unordered_map<std::string, std::string>& a,
    const std::unordered_map<std::string, std::string>& b) noexcept;

// ─── Body diff (Phase 14) ─────────────────────────────────────────────────────

struct BodyDiffResult {
    Status status;
    bool   exact_match;
    bool   normalized_match;
    int64_t length_delta;           // b.size() - a.size()
    double  similarity;             // 0.0 (completely different) – 1.0 (identical)
    size_t  changed_regions;        // approximate count of changed byte ranges
    bool    similarity_approximate; // true if computed via SimHash fallback
};

/**
 * Compare two response bodies.
 * similarity is METADATA only — not a vulnerability verdict.
 */
BodyDiffResult diff_bodies(std::span<const uint8_t> a,
                            std::span<const uint8_t> b) noexcept;

// ─── JSON structural diff (Phase 15) ─────────────────────────────────────────

struct JsonDiffEntry {
    std::string path;    // e.g. "$.user.id"
    std::string change;  // "added", "removed", "changed", "type_changed"
    std::string old_type;
    std::string new_type;
};

struct JsonDiffResult {
    Status status;
    bool   are_equal;
    std::vector<JsonDiffEntry> differences;
    size_t total_keys_a;
    size_t total_keys_b;
    bool   truncated;    // true if diff exceeded MAX_JSON_KEYS
};

/**
 * Structural diff of two JSON bodies.
 * Protected against deep recursion and huge structures.
 */
JsonDiffResult diff_json(std::span<const uint8_t> a,
                          std::span<const uint8_t> b) noexcept;

// ─── Cryptographic hashing (Phase 19-20) ──────────────────────────────────────

struct HashResult {
    Status status;
    std::string hex;     // SHA-256 hex digest (64 chars)
};

/** Streaming SHA-256 over arbitrary bytes. */
HashResult sha256(std::span<const uint8_t> data) noexcept;

// ─── Response fingerprint (Phase 21) ─────────────────────────────────────────

struct ResponseFingerprint {
    Status status;
    uint32_t fp_version;        // fingerprint schema version
    int      status_code;
    std::string body_digest;    // SHA-256 of raw body
    std::string content_type;
    size_t   body_size;
    std::string fingerprint_id; // versioned composite hex
};

ResponseFingerprint compute_fingerprint(
    int status_code,
    const std::unordered_map<std::string, std::string>& headers,
    std::span<const uint8_t> body) noexcept;

// ─── SimHash (Phase 16) ───────────────────────────────────────────────────────

struct SimHashResult {
    Status   status;
    uint64_t hash;
    double   hamming_similarity; // populated only when compared with another hash
};

SimHashResult simhash(std::span<const uint8_t> data) noexcept;
double simhash_similarity(uint64_t a, uint64_t b) noexcept;

// ─── Entropy and binary inspection (Phases 28-30) ─────────────────────────────

struct BinaryInspectResult {
    Status status;
    std::string magic_family;   // "PE", "ELF", "PDF", "ZIP", "HTML", "JSON", "text", "unknown"
    std::string detected_mime;  // coarse detected MIME family
    bool   mime_mismatch;       // true if declared != detected
    double entropy;             // Shannon entropy 0.0–8.0 bits/byte
    double printable_ratio;     // fraction of bytes that are printable ASCII
    size_t size_bytes;
    bool   text_like;
    bool   binary_like;
};

/**
 * Inspect response body without executing it.
 * Returns factual metadata only — entropy alone does not imply vulnerability.
 */
BinaryInspectResult inspect_binary(std::span<const uint8_t> data,
                                    std::string_view declared_content_type) noexcept;

// ─── Multi-pattern scanner / Aho-Corasick (Phase 22) ─────────────────────────

struct PatternMatch {
    size_t offset;
    size_t length;
    uint32_t pattern_id;
};

struct ScanResult {
    Status status;
    std::vector<PatternMatch> matches;
    bool   truncated;  // true if match count would exceed internal limit
};

/** Opaque pattern automaton; thread-safe after construction, immutable. */
class PatternScanner {
public:
    static std::optional<PatternScanner> build(
        const std::vector<std::string>& patterns) noexcept;

    ScanResult scan(std::span<const uint8_t> data) const noexcept;

    size_t pattern_count() const noexcept { return pattern_count_; }
    ~PatternScanner();
    PatternScanner(PatternScanner&&) noexcept;
    PatternScanner& operator=(PatternScanner&&) noexcept;
    PatternScanner(const PatternScanner&) = delete;
    PatternScanner& operator=(const PatternScanner&) = delete;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    size_t pattern_count_ = 0;
    explicit PatternScanner(std::unique_ptr<Impl> impl, size_t n);
};

// ─── Compression guard (Phases 26-27) ────────────────────────────────────────

enum class CompressionFormat { GZIP, DEFLATE };

struct DecompressResult {
    Status status;          // OK, INVALID, TRUNCATED, LIMIT_REACHED
    std::vector<uint8_t> output;
    size_t input_consumed;
    size_t expansion_ratio; // output.size() / input_size * 100 (%)
};

/**
 * Decompress with explicit bomb protection.
 * Returns LIMIT_REACHED if output exceeds MAX_GZIP_OUTPUT_BYTES or
 * expansion ratio exceeds MAX_GZIP_EXPAND_RATIO.
 */
DecompressResult decompress(std::span<const uint8_t> compressed,
                             CompressionFormat fmt) noexcept;

// ─── Feature extraction (Phase 33) ───────────────────────────────────────────

struct FeatureVector {
    Status status;

    // HTTP features
    int     status_code;
    int     status_class;       // 1,2,3,4,5 (HTTP class)

    // Body features
    size_t  body_size;
    double  body_entropy;
    double  printable_ratio;
    bool    is_text_like;
    bool    is_json;

    // Header features
    size_t  header_count;
    bool    has_content_type;
    bool    has_set_cookie;
    bool    has_location;

    // Timing feature (ms; -1 if unknown)
    int64_t elapsed_ms;

    // Similarity (populated when compared against baseline)
    double  body_similarity;
    double  simhash_similarity;
    bool    exact_body_match;
    bool    normalized_body_match;

    // JSON structural features (0 if not JSON)
    size_t  json_key_count;
    int     json_max_depth;

    // Baseline deviation features (-1 if no baseline)
    double  length_z_score;      // signed z-score vs baseline distribution
};

/**
 * Extract ML feature vector from a response.
 * C++ returns FEATURES only — Python makes all security decisions.
 */
FeatureVector extract_features(
    int status_code,
    const std::unordered_map<std::string, std::string>& headers,
    std::span<const uint8_t> body,
    int64_t elapsed_ms = -1) noexcept;

// ─── Capability discovery (Phase 9) ──────────────────────────────────────────

struct Capabilities {
    bool available;
    VersionInfo version;
    bool hashing;
    bool diff;
    bool json_diff;
    bool patterns;
    bool compression;
    bool binary_inspection;
    bool feature_extraction;
    bool simhash;
};

Capabilities get_capabilities() noexcept;

}  // namespace raven
