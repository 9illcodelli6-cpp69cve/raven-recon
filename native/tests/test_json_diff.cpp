#include <gtest/gtest.h>
#include "raven_native.h"
#include <cstring>

namespace {

static raven::JsonDiffResult parse_and_diff(const char* a, const char* b) {
    return raven::diff_json(
        {reinterpret_cast<const uint8_t*>(a), strlen(a)},
        {reinterpret_cast<const uint8_t*>(b), strlen(b)});
}

TEST(JsonDiffTest, IdenticalObjects) {
    auto r = parse_and_diff("{\"a\":1}", "{\"a\":1}");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_TRUE(r.are_equal);
    EXPECT_TRUE(r.differences.empty());
}

TEST(JsonDiffTest, AddedKey) {
    auto r = parse_and_diff("{\"a\":1}", "{\"a\":1,\"b\":2}");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_FALSE(r.are_equal);
    bool found_added = false;
    for (const auto& d : r.differences)
        if (d.change == "added" && d.path.find("b") != std::string::npos)
            found_added = true;
    EXPECT_TRUE(found_added);
}

TEST(JsonDiffTest, RemovedKey) {
    auto r = parse_and_diff("{\"a\":1,\"b\":2}", "{\"a\":1}");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_FALSE(r.are_equal);
}

TEST(JsonDiffTest, ChangedValue) {
    auto r = parse_and_diff("{\"status\":\"ok\"}", "{\"status\":\"fail\"}");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_FALSE(r.are_equal);
    EXPECT_EQ(r.differences.size(), 1u);
    EXPECT_EQ(r.differences[0].change, "changed");
}

TEST(JsonDiffTest, MalformedJsonHandled) {
    auto r = parse_and_diff("{invalid", "{\"a\":1}");
    // Must not crash
    EXPECT_NE(r.status, raven::Status::INTERNAL_ERROR);
}

TEST(JsonDiffTest, NullValues) {
    auto r = parse_and_diff("{\"x\":null}", "{\"x\":null}");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_TRUE(r.are_equal);
}

TEST(JsonDiffTest, TypeChange) {
    auto r = parse_and_diff("{\"id\":\"abc\"}", "{\"id\":123}");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_FALSE(r.are_equal);
    bool type_changed = false;
    for (const auto& d : r.differences)
        if (d.change == "type_changed") type_changed = true;
    EXPECT_TRUE(type_changed);
}

TEST(JsonDiffTest, NestedObjects) {
    auto r = parse_and_diff(
        "{\"user\":{\"id\":1,\"name\":\"alice\"}}",
        "{\"user\":{\"id\":1,\"name\":\"bob\"}}");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_FALSE(r.are_equal);
}

} // namespace
