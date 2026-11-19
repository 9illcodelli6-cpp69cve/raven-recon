#include <gtest/gtest.h>
#include "raven_native.h"

namespace {

TEST(PatternScanTest, SinglePatternFound) {
    auto s = raven::PatternScanner::build({"hello"});
    ASSERT_TRUE(s.has_value());
    const char* text = "say hello world";
    auto r = s->scan({reinterpret_cast<const uint8_t*>(text), strlen(text)});
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_GE(r.matches.size(), 1u);
    EXPECT_EQ(r.matches[0].pattern_id, 0u);
}

TEST(PatternScanTest, MultiplePatterns) {
    auto s = raven::PatternScanner::build({"foo", "bar", "baz"});
    ASSERT_TRUE(s.has_value());
    const char* text = "foobarbaz";
    auto r = s->scan({reinterpret_cast<const uint8_t*>(text), strlen(text)});
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_EQ(r.matches.size(), 3u);
}

TEST(PatternScanTest, PatternNotFound) {
    auto s = raven::PatternScanner::build({"xyz"});
    ASSERT_TRUE(s.has_value());
    const char* text = "hello world";
    auto r = s->scan({reinterpret_cast<const uint8_t*>(text), strlen(text)});
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_TRUE(r.matches.empty());
}

TEST(PatternScanTest, BinaryPatterns) {
    std::vector<uint8_t> pattern = {0x4D, 0x5A};  // PE magic
    std::vector<std::string> patterns = {std::string(pattern.begin(), pattern.end())};
    auto s = raven::PatternScanner::build(patterns);
    ASSERT_TRUE(s.has_value());
    std::vector<uint8_t> data = {0x00, 0x4D, 0x5A, 0x01};
    auto r = s->scan({data.data(), data.size()});
    EXPECT_EQ(r.matches.size(), 1u);
    EXPECT_EQ(r.matches[0].offset, 1u);
}

TEST(PatternScanTest, EmptyPatternList) {
    auto s = raven::PatternScanner::build({});
    ASSERT_TRUE(s.has_value());
    const char* text = "some text";
    auto r = s->scan({reinterpret_cast<const uint8_t*>(text), strlen(text)});
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_TRUE(r.matches.empty());
}

TEST(PatternScanTest, OverlappingPatterns) {
    // "ab" and "abc" should both match in "abc"
    auto s = raven::PatternScanner::build({"ab", "abc"});
    ASSERT_TRUE(s.has_value());
    const char* text = "xabcy";
    auto r = s->scan({reinterpret_cast<const uint8_t*>(text), strlen(text)});
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_GE(r.matches.size(), 2u);
}

} // namespace
