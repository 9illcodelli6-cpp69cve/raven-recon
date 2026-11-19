#include <gtest/gtest.h>
#include "raven_native.h"

namespace {

TEST(FeaturesTest, BasicExtraction) {
    std::unordered_map<std::string, std::string> headers = {
        {"content-type", "application/json"},
        {"content-length", "27"},
    };
    const char* body = "{\"status\":\"ok\",\"data\":null}";
    std::span<const uint8_t> s(reinterpret_cast<const uint8_t*>(body), strlen(body));
    auto r = raven::extract_features(200, headers, s, 150);
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_EQ(r.status_code, 200);
    EXPECT_EQ(r.status_class, 2);
    EXPECT_EQ(r.body_size, 27u);
    EXPECT_EQ(r.elapsed_ms, 150);
    EXPECT_TRUE(r.is_json);
    EXPECT_TRUE(r.has_content_type);
    EXPECT_FALSE(r.has_set_cookie);
}

TEST(FeaturesTest, FeaturesAreNotSecurityDecisions) {
    // The feature vector must not have fields for "vulnerability" or "verified"
    std::unordered_map<std::string, std::string> headers;
    auto r = raven::extract_features(403, headers, {}, -1);
    // Status class = 4, but this is just a number — no "authorization_failure" field
    EXPECT_EQ(r.status_class, 4);
    EXPECT_EQ(r.status, raven::Status::OK);
}

TEST(FeaturesTest, SimilarityFieldsDefaultMinusOne) {
    std::unordered_map<std::string, std::string> headers;
    auto r = raven::extract_features(200, headers, {}, -1);
    EXPECT_DOUBLE_EQ(r.body_similarity, -1.0)
        << "body_similarity must default to -1 when no baseline is available";
}

} // namespace
