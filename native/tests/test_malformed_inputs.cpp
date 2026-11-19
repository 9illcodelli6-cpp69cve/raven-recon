/**
 * Malformed input corpus tests (Phase 42).
 * TARGET-CONTROLLED BYTES ARE HOSTILE INPUT.
 * Every function must not crash, hang, or allocate unboundedly.
 */
#include <gtest/gtest.h>
#include "raven_native.h"
#include <cstring>

namespace {

// ─── Empty inputs ─────────────────────────────────────────────────────────────

TEST(MalformedInputTest, EmptyBodyNormalize) {
    auto r = raven::normalize_body({}, "text/html");
    EXPECT_NE(r.status, raven::Status::INTERNAL_ERROR);
}

TEST(MalformedInputTest, EmptyBodiesDiff) {
    auto r = raven::diff_bodies({}, {});
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_TRUE(r.exact_match);
}

TEST(MalformedInputTest, EmptyJsonDiff) {
    // Zero-length arrays are ill-formed in ISO C++ (MSVC accepted `empty[] = {}`,
    // GCC -Wpedantic -Werror does not). A 1-byte buffer passed with length 0 is
    // the same empty input with a valid non-null pointer.
    const uint8_t empty[1] = {0};
    auto r = raven::diff_json({empty, 0}, {empty, 0});
    // Should handle gracefully — either malformed or ok
    EXPECT_NE(r.status, raven::Status::INTERNAL_ERROR);
}

TEST(MalformedInputTest, EmptyInspect) {
    auto r = raven::inspect_binary({}, "text/html");
    EXPECT_EQ(r.status, raven::Status::OK);
}

TEST(MalformedInputTest, EmptyPatternScan) {
    auto scanner = raven::PatternScanner::build({"hello"});
    ASSERT_TRUE(scanner.has_value());
    auto r = scanner->scan({});
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_TRUE(r.matches.empty());
}

// ─── Single byte ─────────────────────────────────────────────────────────────

TEST(MalformedInputTest, SingleByteInputs) {
    uint8_t b = 0xFF;
    std::span<const uint8_t> s(&b, 1);
    EXPECT_EQ(raven::sha256(s).status, raven::Status::OK);
    EXPECT_EQ(raven::simhash(s).status, raven::Status::OK);
    EXPECT_EQ(raven::inspect_binary(s, "").status, raven::Status::OK);
}

// ─── Random / binary bytes ────────────────────────────────────────────────────

TEST(MalformedInputTest, RandomBytesNormalize) {
    std::vector<uint8_t> data(1024);
    for (size_t i = 0; i < data.size(); ++i)
        data[i] = static_cast<uint8_t>(i * 37 + 13);
    auto r = raven::normalize_body({data.data(), data.size()}, "text/html");
    EXPECT_NE(r.status, raven::Status::INTERNAL_ERROR);
}

// ─── Embedded null bytes ──────────────────────────────────────────────────────

TEST(MalformedInputTest, EmbeddedNullBytes) {
    uint8_t data[] = {0x41, 0x00, 0x42, 0x00, 0x43};
    auto r = raven::sha256({data, sizeof(data)});
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_EQ(r.hex.size(), 64u);
}

TEST(MalformedInputTest, NullByteBodyDiff) {
    uint8_t a[] = {0x41, 0x00, 0x42};
    uint8_t b[] = {0x41, 0x00, 0x43};
    auto r = raven::diff_bodies({a, 3}, {b, 3});
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_FALSE(r.exact_match);
}

// ─── Invalid JSON ─────────────────────────────────────────────────────────────

TEST(MalformedInputTest, TruncatedJson) {
    const char* a = "{\"key\":";
    const char* b = "{\"key\": \"value\"}";
    auto r = raven::diff_json(
        {reinterpret_cast<const uint8_t*>(a), strlen(a)},
        {reinterpret_cast<const uint8_t*>(b), strlen(b)});
    EXPECT_NE(r.status, raven::Status::INTERNAL_ERROR);
}

TEST(MalformedInputTest, DeeplyNestedJsonBeyondLimit) {
    // Construct JSON beyond MAX_JSON_DEPTH
    std::string deep = std::string(100, '{');
    deep += "\"x\":1";
    deep += std::string(100, '}');
    auto r = raven::diff_json(
        {reinterpret_cast<const uint8_t*>(deep.data()), deep.size()},
        {reinterpret_cast<const uint8_t*>(deep.data()), deep.size()});
    // Must not crash — should return MALFORMED or partial result
    EXPECT_NE(r.status, raven::Status::INTERNAL_ERROR);
}

// ─── Repetitive content ───────────────────────────────────────────────────────

TEST(MalformedInputTest, HighlyRepetitiveContent) {
    std::vector<uint8_t> repeated(512 * 1024, 'A');
    auto r = raven::inspect_binary({repeated.data(), repeated.size()}, "text/plain");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_NEAR(r.entropy, 0.0, 0.1) << "All-same bytes should have near-zero entropy";
}

// ─── Truncated gzip magic ────────────────────────────────────────────────────

TEST(MalformedInputTest, TruncatedGzipHeader) {
    uint8_t truncated[] = {0x1f, 0x8b};  // gzip magic only, no more bytes
    auto r = raven::decompress({truncated, 2}, raven::CompressionFormat::GZIP);
    // Must not crash — should return MALFORMED or UNSUPPORTED
    EXPECT_NE(r.status, raven::Status::INTERNAL_ERROR);
}

// ─── Resource limits ──────────────────────────────────────────────────────────

TEST(ResourceLimitTest, PatternScannerExceedsMaxPatterns) {
    std::vector<std::string> patterns(raven::MAX_PATTERN_COUNT + 1, "a");
    auto s = raven::PatternScanner::build(patterns);
    EXPECT_FALSE(s.has_value()) << "Should reject > MAX_PATTERN_COUNT patterns";
}

TEST(ResourceLimitTest, HeaderDiffExceedsMaxHeaders) {
    std::unordered_map<std::string, std::string> big_headers;
    for (size_t i = 0; i < raven::MAX_HEADER_COUNT + 1; ++i)
        big_headers["X-Header-" + std::to_string(i)] = "value";
    auto r = raven::diff_headers(big_headers, {});
    EXPECT_EQ(r.status, raven::Status::INPUT_TOO_LARGE);
}

} // anonymous namespace
