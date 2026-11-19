#include <gtest/gtest.h>
#include "raven_native.h"

namespace {

TEST(CompressionTest, EmptyInput) {
    auto r = raven::decompress({}, raven::CompressionFormat::GZIP);
    // Empty input → either OK with empty output or MALFORMED, never crash
    EXPECT_NE(r.status, raven::Status::INTERNAL_ERROR);
}

TEST(CompressionTest, TruncatedGzip) {
    uint8_t bad[] = {0x1f, 0x8b, 0x00};
    auto r = raven::decompress({bad, 3}, raven::CompressionFormat::GZIP);
    EXPECT_NE(r.status, raven::Status::INTERNAL_ERROR);
}

TEST(CompressionTest, AllZerosBomb) {
    // A valid-looking but all-zeros blob — should not crash
    std::vector<uint8_t> zeros(4096, 0);
    auto r = raven::decompress({zeros.data(), zeros.size()}, raven::CompressionFormat::GZIP);
    EXPECT_NE(r.status, raven::Status::INTERNAL_ERROR);
}

TEST(CompressionTest, ConstantsAreReasonable) {
    EXPECT_GE(raven::MAX_GZIP_OUTPUT_BYTES, static_cast<size_t>(1 * 1024 * 1024));
    EXPECT_LE(raven::MAX_GZIP_EXPAND_RATIO, static_cast<size_t>(1024));
}

} // namespace
