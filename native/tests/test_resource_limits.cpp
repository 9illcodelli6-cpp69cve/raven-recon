#include <gtest/gtest.h>
#include "raven_native.h"

namespace {

TEST(ResourceLimitTest, MaxBodyBytesConstantSane) {
    EXPECT_EQ(raven::MAX_BODY_BYTES, 10u * 1024u * 1024u);
}

TEST(ResourceLimitTest, MaxNormalizedBytesSane) {
    EXPECT_EQ(raven::MAX_NORMALIZED_BYTES, 8u * 1024u);
}

TEST(ResourceLimitTest, MaxHeaderCountSane) {
    EXPECT_GE(raven::MAX_HEADER_COUNT, 64u);
}

TEST(ResourceLimitTest, MaxJsonDepthSane) {
    EXPECT_LE(raven::MAX_JSON_DEPTH, 256u);
    EXPECT_GE(raven::MAX_JSON_DEPTH, 8u);
}

TEST(ResourceLimitTest, MaxPatternCountSane) {
    EXPECT_GE(raven::MAX_PATTERN_COUNT, 100u);
}

TEST(ResourceLimitTest, ABIVersionPositive) {
    EXPECT_GE(raven::NATIVE_ABI_VERSION, 1u);
}

} // namespace
