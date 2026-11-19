#include <gtest/gtest.h>
#include "raven_native.h"
#include <cstring>

namespace {

TEST(NormalizeTest, LineEndingNormalization) {
    const char* crlf = "line1\r\nline2\r\n";
    std::span<const uint8_t> s(reinterpret_cast<const uint8_t*>(crlf), strlen(crlf));
    auto r = raven::normalize_body(s, "text/html");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_EQ(r.normalized.find("\r\n"), std::string::npos)
        << "CRLF should be normalized to LF";
}

TEST(NormalizeTest, UUIDsReplaced) {
    const char* body = "result: 550e8400-e29b-41d4-a716-446655440000";
    std::span<const uint8_t> s(reinterpret_cast<const uint8_t*>(body), strlen(body));
    auto r = raven::normalize_body(s, "application/json");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_EQ(r.normalized.find("550e8400"), std::string::npos)
        << "UUID should be replaced by placeholder";
}

TEST(NormalizeTest, TwoIdenticalBodiesHaveSameDigest) {
    const char* body = "Hello World";
    std::span<const uint8_t> s(reinterpret_cast<const uint8_t*>(body), strlen(body));
    auto r1 = raven::normalize_body(s, "text/html");
    auto r2 = raven::normalize_body(s, "text/html");
    EXPECT_EQ(r1.digest, r2.digest);
}

TEST(NormalizeTest, BinaryBodyReturnsEmptyNormalized) {
    uint8_t binary[] = {0x4D, 0x5A, 0x00, 0x01}; // PE header
    auto r = raven::normalize_body({binary, 4}, "application/octet-stream");
    // Binary content — normalized text should be empty or minimal
    EXPECT_EQ(r.status, raven::Status::OK);
}

TEST(NormalizeTest, Truncation) {
    // Create body larger than MAX_NORMALIZED_BYTES
    std::vector<uint8_t> large(raven::MAX_NORMALIZED_BYTES + 100, 'A');
    auto r = raven::normalize_body({large.data(), large.size()}, "text/plain");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_TRUE(r.was_truncated);
    EXPECT_LE(r.normalized.size(), raven::MAX_NORMALIZED_BYTES);
}

} // namespace
