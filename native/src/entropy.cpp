/**
 * RAVEN Native — Shannon entropy and binary inspection (Phases 28-30).
 *
 * Entropy is METADATA only. High entropy does not imply encryption/secrets.
 * Binary family detection uses magic bytes only — no file execution.
 */
#include "raven_native.h"
#include <array>
#include <cmath>
#include <algorithm>

namespace raven {

// Shannon entropy: sum(-p_i * log2(p_i)) over byte value frequencies
static double compute_entropy(std::span<const uint8_t> data) noexcept {
    if (data.empty()) return 0.0;

    std::array<uint64_t, 256> freq{};
    for (uint8_t b : data) freq[b]++;

    double entropy = 0.0;
    const double n = static_cast<double>(data.size());
    for (size_t i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = freq[i] / n;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// Printable ASCII ratio (0x20–0x7E + common whitespace)
static double compute_printable_ratio(std::span<const uint8_t> data) noexcept {
    if (data.empty()) return 1.0;
    size_t printable = 0;
    for (uint8_t b : data) {
        if ((b >= 0x20 && b <= 0x7E) || b == '\n' || b == '\r' || b == '\t')
            ++printable;
    }
    return static_cast<double>(printable) / static_cast<double>(data.size());
}

// Magic byte family detection (covers most RAVEN-relevant types)
static std::string detect_magic_family(std::span<const uint8_t> data) noexcept {
    if (data.size() >= 2 && data[0] == 'P' && data[1] == 'K')            return "ZIP";
    if (data.size() >= 4 && data[0] == 0x7F && data[1] == 'E'
                         && data[2] == 'L'  && data[3] == 'F')           return "ELF";
    if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z')            return "PE";
    if (data.size() >= 4 && data[0] == 0x25 && data[1] == 0x50
                         && data[2] == 0x44 && data[3] == 0x46)          return "PDF";
    if (data.size() >= 3 && data[0] == 0x1F && data[1] == 0x8B)          return "GZIP";
    if (data.size() >= 6 && data[0] == 'G' && data[1] == 'I'
                         && data[2] == 'F')                               return "GIF";
    if (data.size() >= 4 && data[0] == 0xFF && data[1] == 0xD8
                         && data[2] == 0xFF)                              return "JPEG";
    if (data.size() >= 8 && data[0] == 0x89 && data[1] == 'P'
                         && data[2] == 'N'  && data[3] == 'G')           return "PNG";
    if (data.size() >= 4 && ((data[0] == 0x00 && data[1] == 0x00
                              && data[2] == 0x00) || data[0] == 0xFF))   return "MP4-like";

    // Sniff for text types — look at first 512 bytes
    auto sample = data.subspan(0, std::min(data.size(), size_t{512}));
    bool has_null = false;
    for (uint8_t b : sample) if (b == 0) { has_null = true; break; }
    if (has_null) return "binary";

    auto pr = compute_printable_ratio(sample);
    if (pr >= 0.90) {
        // Try to distinguish HTML/JSON/XML
        std::string_view sv(reinterpret_cast<const char*>(data.data()),
                            std::min(data.size(), size_t{128}));
        if (sv.find("<!DOCTYPE") != std::string_view::npos
         || sv.find("<html")     != std::string_view::npos
         || sv.find("<HTML")     != std::string_view::npos) return "HTML";
        if (!sv.empty() && (sv[0] == '{' || sv[0] == '['))  return "JSON";
        if (!sv.empty() && sv[0] == '<')                     return "XML";
        return "text";
    }
    return "unknown";
}

// Coarse MIME family from declared content-type
static std::string declared_mime_family(std::string_view ct) noexcept {
    if (ct.find("text/html")        != std::string_view::npos) return "HTML";
    if (ct.find("application/json") != std::string_view::npos) return "JSON";
    if (ct.find("application/xml")  != std::string_view::npos) return "XML";
    if (ct.find("text/xml")         != std::string_view::npos) return "XML";
    if (ct.find("text/")            != std::string_view::npos) return "text";
    if (ct.find("image/")           != std::string_view::npos) return "image";
    if (ct.find("application/pdf")  != std::string_view::npos) return "PDF";
    if (ct.find("application/zip")  != std::string_view::npos) return "ZIP";
    if (ct.find("application/octet-stream") != std::string_view::npos) return "binary";
    return "unknown";
}

BinaryInspectResult inspect_binary(std::span<const uint8_t> data,
                                    std::string_view declared_content_type) noexcept {
    if (data.size() > MAX_BODY_BYTES)
        return {Status::INPUT_TOO_LARGE};

    BinaryInspectResult r{};
    r.status         = Status::OK;
    r.size_bytes     = data.size();
    r.magic_family   = detect_magic_family(data);
    r.detected_mime  = r.magic_family;
    r.entropy        = compute_entropy(data);
    r.printable_ratio = compute_printable_ratio(data);
    r.text_like      = r.printable_ratio >= 0.85;
    r.binary_like    = !r.text_like && r.printable_ratio < 0.50;

    std::string decl = declared_mime_family(declared_content_type);
    // Mismatch: declared is text-ish but detected is binary-ish
    r.mime_mismatch  = (decl == "HTML" || decl == "JSON" || decl == "text")
                    && (r.magic_family == "PE" || r.magic_family == "ELF"
                        || r.magic_family == "binary" || r.magic_family == "ZIP");

    return r;
}

// Expose entropy calculation directly
double compute_shannon_entropy(std::span<const uint8_t> data) noexcept {
    return compute_entropy(data);
}

} // namespace raven
