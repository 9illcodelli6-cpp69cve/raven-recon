#include <gtest/gtest.h>
#include "raven_native.h"

namespace {

TEST(BinaryInspectTest, GzipMagic) {
    uint8_t gz[] = {0x1f, 0x8b, 0x08, 0x00};
    auto r = raven::inspect_binary({gz, 4}, "application/gzip");
    EXPECT_EQ(r.magic_family, "GZIP");
}

TEST(BinaryInspectTest, ZipMagic) {
    uint8_t pk[] = {0x50, 0x4B, 0x03, 0x04};
    auto r = raven::inspect_binary({pk, 4}, "application/zip");
    EXPECT_EQ(r.magic_family, "ZIP");
}

TEST(BinaryInspectTest, JsonDetected) {
    const char* json = "{\"status\":\"ok\",\"data\":[1,2,3]}";
    std::span<const uint8_t> s(reinterpret_cast<const uint8_t*>(json), strlen(json));
    auto r = raven::inspect_binary(s, "application/json");
    EXPECT_EQ(r.magic_family, "JSON");
    EXPECT_TRUE(r.text_like);
}

TEST(BinaryInspectTest, MimeMismatch) {
    // PE file declared as text/html
    uint8_t pe[] = {0x4D, 0x5A, 0x90, 0x00};
    auto r = raven::inspect_binary({pe, 4}, "text/html");
    EXPECT_TRUE(r.mime_mismatch);
}

TEST(BinaryInspectTest, SizeReported) {
    std::vector<uint8_t> data(1234, 0x41);
    auto r = raven::inspect_binary({data.data(), data.size()}, "text/plain");
    EXPECT_EQ(r.size_bytes, 1234u);
}

} // namespace
