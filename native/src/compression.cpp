/**
 * RAVEN Native — Decompression with bomb protection (Phases 26-27).
 *
 * Uses zlib for gzip/deflate. Enforces:
 * - MAX_GZIP_OUTPUT_BYTES (50 MB)
 * - MAX_GZIP_EXPAND_RATIO (128x)
 *
 * Returns controlled status codes; never terminates RAVEN on malformed input.
 */
#include "raven_native.h"

// Attempt to use zlib if available; otherwise stub
#if __has_include(<zlib.h>)
#  include <zlib.h>
#  define RAVEN_HAS_ZLIB 1
#else
#  define RAVEN_HAS_ZLIB 0
#endif

namespace raven {

DecompressResult decompress(std::span<const uint8_t> compressed,
                             CompressionFormat fmt) noexcept {
#if RAVEN_HAS_ZLIB
    if (compressed.empty())
        return {Status::OK, {}, 0, 0};

    if (compressed.size() > MAX_BODY_BYTES)
        return {Status::INPUT_TOO_LARGE, {}, 0, 0};

    // Check expansion limit eagerly
    // (conservative: actual ratio measured after decompression)
    constexpr size_t INITIAL_ALLOC = 64 * 1024;

    z_stream zs{};
    int wbits = 15;  // deflate
    if (fmt == CompressionFormat::GZIP)
        wbits += 16;  // gzip wrapper detection

    if (inflateInit2(&zs, wbits) != Z_OK)
        return {Status::INTERNAL_ERROR, {}, 0, 0};

    struct Zguard { z_stream* z; ~Zguard(){ inflateEnd(z); } } g{&zs};

    std::vector<uint8_t> output;
    output.reserve(std::min(compressed.size() * 4, INITIAL_ALLOC));

    zs.next_in  = const_cast<Bytef*>(compressed.data());
    zs.avail_in = static_cast<uInt>(compressed.size());

    std::array<uint8_t, 32768> chunk{};
    size_t input_consumed = 0;
    int ret = Z_OK;

    while (ret == Z_OK || ret == Z_BUF_ERROR) {
        zs.next_out  = chunk.data();
        zs.avail_out = static_cast<uInt>(chunk.size());

        ret = inflate(&zs, Z_NO_FLUSH);
        size_t produced = chunk.size() - zs.avail_out;

        output.insert(output.end(), chunk.begin(), chunk.begin() + produced);

        // Bomb check
        if (output.size() > MAX_GZIP_OUTPUT_BYTES)
            return {Status::LIMIT_REACHED, {}, zs.total_in, 0};

        if (compressed.size() > 0 && output.size() > 0) {
            size_t ratio = output.size() / compressed.size();
            if (ratio > MAX_GZIP_EXPAND_RATIO)
                return {Status::LIMIT_REACHED, {}, zs.total_in, ratio};
        }

        if (ret == Z_STREAM_END) break;
        // Z_BUF_ERROR with nothing produced means inflate cannot make progress:
        // the input ran out before the end of the stream (truncated / garbage).
        // Without this check the loop spun forever at 100% CPU on a truncated
        // gzip body (latent on Windows builds, where zlib was not compiled in).
        if (ret == Z_BUF_ERROR && produced == 0)
            return {Status::MALFORMED, {}, zs.total_in, 0};
        if (ret != Z_OK && ret != Z_BUF_ERROR)
            return {Status::MALFORMED, {}, zs.total_in, 0};
    }

    input_consumed = zs.total_in;
    size_t ratio = (compressed.size() > 0)
                   ? (output.size() / compressed.size())
                   : 0;

    return {Status::OK, std::move(output), input_consumed, ratio};
#else
    (void)compressed; (void)fmt;
    return {Status::UNSUPPORTED, {}, 0, 0};
#endif
}

} // namespace raven
