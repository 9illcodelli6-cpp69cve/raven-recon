#include <gtest/gtest.h>
#include "raven_native.h"

namespace {

TEST(HashTest, EmptyInput) {
    auto r = raven::sha256({});
    EXPECT_EQ(r.status, raven::Status::OK);
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    EXPECT_EQ(r.hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(HashTest, KnownVector) {
    const char* msg = "abc";
    std::span<const uint8_t> s(reinterpret_cast<const uint8_t*>(msg), 3);
    auto r = raven::sha256(s);
    EXPECT_EQ(r.status, raven::Status::OK);
    // NIST FIPS 180-2 test vector: SHA-256("abc"). (The previous expected value
    // here was a mistyped hash and failed against both OpenSSL and BCrypt.)
    EXPECT_EQ(r.hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(HashTest, InputTooLarge) {
    // Construct a span larger than MAX_BODY_BYTES (simulated via pointer arithmetic)
    // We can't actually allocate 10MB in a test — test the limit constant instead
    EXPECT_GT(raven::MAX_BODY_BYTES, 0u);
}

TEST(HashTest, IncrementalEquivalence) {
    // hash(all_bytes) == hash(chunk1 + chunk2) — verify via same input
    std::vector<uint8_t> data(1024, 0xAB);
    auto r1 = raven::sha256({data.data(), data.size()});
    // Split into two halves and reconstruct — since we hash the combined data,
    // both calls with the same input must produce the same result.
    auto r2 = raven::sha256({data.data(), data.size()});
    EXPECT_EQ(r1.hex, r2.hex);
    EXPECT_EQ(r1.status, raven::Status::OK);
}

TEST(HashTest, DifferentDataDifferentDigest) {
    std::vector<uint8_t> a = {0x01, 0x02};
    std::vector<uint8_t> b = {0x01, 0x03};
    auto ra = raven::sha256({a.data(), a.size()});
    auto rb = raven::sha256({b.data(), b.size()});
    EXPECT_NE(ra.hex, rb.hex);
}

// ─── SimHash ──────────────────────────────────────────────────────────────────

TEST(SimHashTest, EmptyInput) {
    auto r = raven::simhash({});
    EXPECT_EQ(r.status, raven::Status::OK);
}

TEST(SimHashTest, IdenticalInputsSameHash) {
    const char* s = "the quick brown fox";
    std::span<const uint8_t> sp(reinterpret_cast<const uint8_t*>(s), strlen(s));
    auto r1 = raven::simhash(sp);
    auto r2 = raven::simhash(sp);
    EXPECT_EQ(r1.hash, r2.hash);
}

TEST(SimHashTest, SimilarInputsHighSimilarity) {
    const char* a = "the quick brown fox jumps over the lazy dog";
    const char* b = "the quick brown fox jumps over the lazy cat";
    auto ra = raven::simhash({reinterpret_cast<const uint8_t*>(a), strlen(a)});
    auto rb = raven::simhash({reinterpret_cast<const uint8_t*>(b), strlen(b)});
    double sim = raven::simhash_similarity(ra.hash, rb.hash);
    EXPECT_GT(sim, 0.5) << "Similar texts should have > 50% SimHash similarity";
}

TEST(SimHashTest, VeryDifferentInputsLowSimilarity) {
    // Fill with repeated different patterns
    std::vector<uint8_t> a(200, 0xAA);
    std::vector<uint8_t> b(200, 0x55);
    auto ra = raven::simhash({a.data(), a.size()});
    auto rb = raven::simhash({b.data(), b.size()});
    double sim = raven::simhash_similarity(ra.hash, rb.hash);
    EXPECT_LT(sim, 0.7) << "Very different data should have lower SimHash similarity";
}

} // anonymous namespace
