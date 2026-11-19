#include <gtest/gtest.h>
#include "raven_native.h"
#include <cstring>

namespace {

// ─── Header diff ──────────────────────────────────────────────────────────────

TEST(HeaderDiffTest, Identical) {
    std::unordered_map<std::string, std::string> h = {{"content-type", "text/html"}};
    auto r = raven::diff_headers(h, h);
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_TRUE(r.added.empty());
    EXPECT_TRUE(r.removed.empty());
    EXPECT_TRUE(r.changed.empty());
}

TEST(HeaderDiffTest, AddedHeader) {
    std::unordered_map<std::string, std::string> a, b;
    b["x-new"] = "value";
    auto r = raven::diff_headers(a, b);
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_EQ(r.added.size(), 1u);
    EXPECT_EQ(r.added[0], "x-new");
    EXPECT_TRUE(r.removed.empty());
}

TEST(HeaderDiffTest, RemovedHeader) {
    std::unordered_map<std::string, std::string> a = {{"x-old", "v"}}, b;
    auto r = raven::diff_headers(a, b);
    EXPECT_EQ(r.removed.size(), 1u);
}

TEST(HeaderDiffTest, ChangedHeader) {
    std::unordered_map<std::string, std::string> a = {{"content-type", "text/html"}};
    std::unordered_map<std::string, std::string> b = {{"content-type", "text/plain"}};
    auto r = raven::diff_headers(a, b);
    EXPECT_EQ(r.changed.size(), 1u);
    EXPECT_EQ(r.changed[0].name, "content-type");
    EXPECT_EQ(r.changed[0].old_value, "text/html");
    EXPECT_EQ(r.changed[0].new_value, "text/plain");
}

TEST(HeaderDiffTest, NoSecurityVerdict) {
    // Ensure diff result contains only structural info — no verdict field
    std::unordered_map<std::string, std::string> a = {{"x-auth", "user1"}};
    std::unordered_map<std::string, std::string> b = {{"x-auth", "user2"}};
    auto r = raven::diff_headers(a, b);
    EXPECT_EQ(r.status, raven::Status::OK);
    // No authorization_failure field exists — structural only
    EXPECT_EQ(r.changed.size(), 1u);
}

// ─── Body diff ────────────────────────────────────────────────────────────────

TEST(BodyDiffTest, ExactMatch) {
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    auto r = raven::diff_bodies({data.data(), data.size()}, {data.data(), data.size()});
    EXPECT_TRUE(r.exact_match);
    EXPECT_DOUBLE_EQ(r.similarity, 1.0);
    EXPECT_EQ(r.length_delta, 0);
}

TEST(BodyDiffTest, CompletelyDifferent) {
    std::vector<uint8_t> a(100, 0xAA);
    std::vector<uint8_t> b(100, 0x55);
    auto r = raven::diff_bodies({a.data(), a.size()}, {b.data(), b.size()});
    EXPECT_FALSE(r.exact_match);
    EXPECT_LT(r.similarity, 1.0);
}

TEST(BodyDiffTest, LengthDelta) {
    std::vector<uint8_t> a(10, 'a');
    std::vector<uint8_t> b(15, 'a');
    auto r = raven::diff_bodies({a.data(), a.size()}, {b.data(), b.size()});
    EXPECT_EQ(r.length_delta, 5);
}

} // namespace
