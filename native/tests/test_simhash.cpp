#include <gtest/gtest.h>
#include "raven_native.h"

namespace {

TEST(SimHashTest, SameInputSameHash) {
    const char* text = "hello world";
    std::span<const uint8_t> s(reinterpret_cast<const uint8_t*>(text), strlen(text));
    auto r1 = raven::simhash(s);
    auto r2 = raven::simhash(s);
    EXPECT_EQ(r1.hash, r2.hash);
}

TEST(SimHashTest, IdenticalInputSimilarityOne) {
    auto h = raven::simhash({reinterpret_cast<const uint8_t*>("abc"), 3}).hash;
    EXPECT_DOUBLE_EQ(raven::simhash_similarity(h, h), 1.0);
}

TEST(SimHashTest, OppositeHashesLowSimilarity) {
    uint64_t a = 0x0000000000000000ULL;
    uint64_t b = 0xFFFFFFFFFFFFFFFFULL;
    EXPECT_DOUBLE_EQ(raven::simhash_similarity(a, b), 0.0);
}

} // namespace
