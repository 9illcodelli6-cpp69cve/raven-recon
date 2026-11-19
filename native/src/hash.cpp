/**
 * RAVEN Native — SHA-256 implementation using platform crypto primitives.
 *
 * Windows: BCryptHashData (CNG)
 * Linux/macOS: OpenSSL EVP (or fallback to portable implementation)
 *
 * We do NOT implement SHA-256 manually (Phase 19 invariant).
 * No target data is ever transmitted — this is a pure local computation.
 */
#include "raven_native.h"
#include <array>
#include <cstring>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
namespace {
struct BcryptAlg {
    BCRYPT_ALG_HANDLE h = nullptr;
    BcryptAlg() noexcept {
        BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    }
    ~BcryptAlg() noexcept { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};
static BcryptAlg g_alg;
} // namespace
#else
#  include <openssl/evp.h>
#endif

namespace raven {

static std::string bytes_to_hex(const uint8_t* data, size_t len) noexcept {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
    return ss.str();
}

HashResult sha256(std::span<const uint8_t> data) noexcept {
    if (data.size() > MAX_BODY_BYTES)
        return {Status::INPUT_TOO_LARGE, {}};

    constexpr size_t SHA256_BYTES = 32;
    uint8_t digest[SHA256_BYTES] = {};

#ifdef _WIN32
    if (!g_alg.h) return {Status::INTERNAL_ERROR, {}};

    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD hashObjSize = 0, retLen = 0;
    if (BCryptGetProperty(g_alg.h, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&hashObjSize), sizeof(DWORD),
                          &retLen, 0) != 0)
        return {Status::INTERNAL_ERROR, {}};

    std::vector<uint8_t> hashObj(hashObjSize);
    if (BCryptCreateHash(g_alg.h, &hHash, hashObj.data(), hashObjSize,
                         nullptr, 0, 0) != 0)
        return {Status::INTERNAL_ERROR, {}};

    struct HashGuard {
        BCRYPT_HASH_HANDLE h;
        ~HashGuard() { if (h) BCryptDestroyHash(h); }
    } guard{hHash};

    if (BCryptHashData(hHash,
                       const_cast<PUCHAR>(data.data()),
                       static_cast<ULONG>(data.size()), 0) != 0)
        return {Status::INTERNAL_ERROR, {}};

    if (BCryptFinishHash(hHash, digest, SHA256_BYTES, 0) != 0)
        return {Status::INTERNAL_ERROR, {}};

#else
    // OpenSSL EVP path
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {Status::INTERNAL_ERROR, {}};
    struct CtxGuard { EVP_MD_CTX* c; ~CtxGuard(){ EVP_MD_CTX_free(c); } } g{ctx};
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr))
        return {Status::INTERNAL_ERROR, {}};
    if (!EVP_DigestUpdate(ctx, data.data(), data.size()))
        return {Status::INTERNAL_ERROR, {}};
    unsigned dlen = SHA256_BYTES;
    if (!EVP_DigestFinal_ex(ctx, digest, &dlen))
        return {Status::INTERNAL_ERROR, {}};
#endif

    return {Status::OK, bytes_to_hex(digest, SHA256_BYTES)};
}

} // namespace raven
