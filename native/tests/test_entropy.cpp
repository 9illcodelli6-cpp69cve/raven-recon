#include <gtest/gtest.h>
#include "raven_native.h"

namespace {

TEST(EntropyTest, UniformByteHighEntropy) {
    // Uniform distribution over 256 values → max entropy = 8.0 bits
    std::vector<uint8_t> data(256);
    for (int i = 0; i < 256; ++i) data[i] = static_cast<uint8_t>(i);
    auto r = raven::inspect_binary({data.data(), data.size()}, "application/octet-stream");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_NEAR(r.entropy, 8.0, 0.01);
}

TEST(EntropyTest, SingleByteValueLowEntropy) {
    std::vector<uint8_t> data(256, 0x41);
    auto r = raven::inspect_binary({data.data(), data.size()}, "text/plain");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_NEAR(r.entropy, 0.0, 0.01);
}

TEST(EntropyTest, PrintableRatioHighForText) {
    const char* text = "Hello, World! This is readable text.";
    std::span<const uint8_t> s(reinterpret_cast<const uint8_t*>(text), strlen(text));
    auto r = raven::inspect_binary(s, "text/plain");
    EXPECT_EQ(r.status, raven::Status::OK);
    EXPECT_GE(r.printable_ratio, 0.9);
    EXPECT_TRUE(r.text_like);
}

TEST(EntropyTest, PrintableRatioLowForBinary) {
    std::vector<uint8_t> data(256);
    for (int i = 0; i < 256; ++i) data[i] = static_cast<uint8_t>(i);
    auto r = raven::inspect_binary({data.data(), data.size()}, "application/octet-stream");
    EXPECT_LT(r.printable_ratio, 0.7);
}

TEST(EntropyTest, PEMagicDetection) {
    uint8_t pe[] = {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00};
    auto r = raven::inspect_binary({pe, 8}, "application/octet-stream");
    EXPECT_EQ(r.magic_family, "PE");
}

TEST(EntropyTest, HTMLDetection) {
    const char* html = "<!DOCTYPE html><html><body>test</body></html>";
    std::span<const uint8_t> s(reinterpret_cast<const uint8_t*>(html), strlen(html));
    auto r = raven::inspect_binary(s, "text/html");
    EXPECT_EQ(r.magic_family, "HTML");
}

} // namespace
