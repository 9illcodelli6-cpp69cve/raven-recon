/**
 * RAVEN Native — pybind11 Python bridge (Phase 6).
 *
 * Exposes raven:: functions as the Python module `_raven_native`.
 * The module is always importable; functions return Python dicts
 * with a "status" field.
 *
 * ABI boundary rules:
 * - No C++ exceptions cross this boundary (all caught, mapped to status).
 * - No Python objects stored in C++ state.
 * - PatternScanner is exposed as an opaque Python object.
 * - GIL released only for CPU-heavy, Python-free work.
 */
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "raven_native.h"

namespace py = pybind11;

static py::dict status_to_dict(raven::Status s) {
    std::string msg;
    switch (s) {
        case raven::Status::OK:              msg = "ok"; break;
        case raven::Status::INPUT_TOO_LARGE: msg = "input_too_large"; break;
        case raven::Status::INVALID_INPUT:   msg = "invalid_input"; break;
        case raven::Status::LIMIT_REACHED:   msg = "limit_reached"; break;
        case raven::Status::TRUNCATED:       msg = "truncated"; break;
        case raven::Status::MALFORMED:       msg = "malformed"; break;
        case raven::Status::UNSUPPORTED:     msg = "unsupported"; break;
        default:                              msg = "internal_error"; break;
    }
    py::dict d;
    d["status"] = msg;
    d["ok"]     = (s == raven::Status::OK);
    return d;
}

static std::span<const uint8_t> bytes_span(const py::bytes& b) {
    char* data; Py_ssize_t size;
    PyBytes_AsStringAndSize(b.ptr(), &data, &size);
    return {reinterpret_cast<const uint8_t*>(data), static_cast<size_t>(size)};
}

PYBIND11_MODULE(_raven_native, m) {
    m.doc() = "RAVEN native analysis engine v6 — compute-only, no networking";

    // ── Version & capabilities ───────────────────────────────────────────────
    m.def("get_version", []() {
        auto v = raven::get_version();
        py::dict d;
        d["major"]       = v.major_ver;
        d["minor"]       = v.minor_ver;
        d["patch"]       = v.patch_ver;
        d["abi_version"] = v.abi_version;
        d["compiler"]    = v.compiler_id;
        d["arch"]        = v.arch;
        return d;
    });

    m.def("get_capabilities", []() {
        auto c = raven::get_capabilities();
        py::dict d;
        d["available"]          = c.available;
        d["hashing"]            = c.hashing;
        d["diff"]               = c.diff;
        d["json_diff"]          = c.json_diff;
        d["patterns"]           = c.patterns;
        d["compression"]        = c.compression;
        d["binary_inspection"]  = c.binary_inspection;
        d["feature_extraction"] = c.feature_extraction;
        d["simhash"]            = c.simhash;
        return d;
    });

    // ── SHA-256 ──────────────────────────────────────────────────────────────
    m.def("sha256", [](const py::bytes& data) {
        auto r = raven::sha256(bytes_span(data));
        auto d = status_to_dict(r.status);
        d["hex"] = r.hex;
        return d;
    }, py::arg("data"),
       "Compute SHA-256 hex digest. Returns dict with 'hex' key.");

    // ── Normalization ────────────────────────────────────────────────────────
    m.def("normalize_body", [](const py::bytes& body, const std::string& ct) {
        auto r = raven::normalize_body(bytes_span(body), ct);
        auto d = status_to_dict(r.status);
        d["normalized"]    = py::bytes(r.normalized);
        d["digest"]        = r.digest;
        d["was_truncated"] = r.was_truncated;
        return d;
    }, py::arg("body"), py::arg("content_type") = "",
       "Normalize response body for comparison.");

    // ── Header diff ──────────────────────────────────────────────────────────
    m.def("diff_headers", [](const py::dict& a, const py::dict& b) {
        std::unordered_map<std::string, std::string> ma, mb;
        for (auto& [k, v] : a) ma[py::str(k)] = py::str(v);
        for (auto& [k, v] : b) mb[py::str(k)] = py::str(v);
        auto r = raven::diff_headers(ma, mb);
        auto d = status_to_dict(r.status);
        d["added"]   = r.added;
        d["removed"] = r.removed;
        py::list changed;
        for (auto& c : r.changed) {
            py::dict cd;
            cd["name"]      = c.name;
            cd["old_value"] = c.old_value;
            cd["new_value"] = c.new_value;
            changed.append(cd);
        }
        d["changed"] = changed;
        return d;
    }, py::arg("a"), py::arg("b"));

    // ── Body diff ────────────────────────────────────────────────────────────
    m.def("diff_bodies", [](const py::bytes& a, const py::bytes& b) {
        auto r = raven::diff_bodies(bytes_span(a), bytes_span(b));
        auto d = status_to_dict(r.status);
        d["exact_match"]            = r.exact_match;
        d["normalized_match"]       = r.normalized_match;
        d["length_delta"]           = r.length_delta;
        d["similarity"]             = r.similarity;
        d["changed_regions"]        = r.changed_regions;
        d["similarity_approximate"] = r.similarity_approximate;
        return d;
    }, py::arg("a"), py::arg("b"));

    // ── JSON diff ────────────────────────────────────────────────────────────
    m.def("diff_json", [](const py::bytes& a, const py::bytes& b) {
        auto r = raven::diff_json(bytes_span(a), bytes_span(b));
        auto d = status_to_dict(r.status);
        d["are_equal"]    = r.are_equal;
        d["total_keys_a"] = r.total_keys_a;
        d["total_keys_b"] = r.total_keys_b;
        d["truncated"]    = r.truncated;
        py::list diffs;
        for (auto& e : r.differences) {
            py::dict ed;
            ed["path"]     = e.path;
            ed["change"]   = e.change;
            ed["old_type"] = e.old_type;
            ed["new_type"] = e.new_type;
            diffs.append(ed);
        }
        d["differences"] = diffs;
        return d;
    }, py::arg("a"), py::arg("b"));

    // ── SimHash ──────────────────────────────────────────────────────────────
    m.def("simhash", [](const py::bytes& data) {
        auto r = raven::simhash(bytes_span(data));
        auto d = status_to_dict(r.status);
        d["hash"] = r.hash;
        return d;
    }, py::arg("data"));

    m.def("simhash_similarity", [](uint64_t a, uint64_t b) {
        return raven::simhash_similarity(a, b);
    }, py::arg("a"), py::arg("b"));

    // ── Binary inspection ────────────────────────────────────────────────────
    m.def("inspect_binary", [](const py::bytes& data, const std::string& ct) {
        auto r = raven::inspect_binary(bytes_span(data), ct);
        auto d = status_to_dict(r.status);
        d["magic_family"]    = r.magic_family;
        d["detected_mime"]   = r.detected_mime;
        d["mime_mismatch"]   = r.mime_mismatch;
        d["entropy"]         = r.entropy;
        d["printable_ratio"] = r.printable_ratio;
        d["size_bytes"]      = r.size_bytes;
        d["text_like"]       = r.text_like;
        d["binary_like"]     = r.binary_like;
        return d;
    }, py::arg("data"), py::arg("content_type") = "");

    // ── Response fingerprint ─────────────────────────────────────────────────
    m.def("compute_fingerprint", [](int status, const py::dict& hdrs,
                                     const py::bytes& body) {
        std::unordered_map<std::string, std::string> h;
        for (auto& [k, v] : hdrs) h[py::str(k)] = py::str(v);
        auto r = raven::compute_fingerprint(status, h, bytes_span(body));
        auto d = status_to_dict(r.status);
        d["fp_version"]     = r.fp_version;
        d["status_code"]    = r.status_code;
        d["body_digest"]    = r.body_digest;
        d["content_type"]   = r.content_type;
        d["body_size"]      = r.body_size;
        d["fingerprint_id"] = r.fingerprint_id;
        return d;
    }, py::arg("status"), py::arg("headers"), py::arg("body"));

    // ── Feature extraction ───────────────────────────────────────────────────
    m.def("extract_features", [](int status, const py::dict& hdrs,
                                  const py::bytes& body, int64_t elapsed_ms) {
        std::unordered_map<std::string, std::string> h;
        for (auto& [k, v] : hdrs) h[py::str(k)] = py::str(v);
        auto r = raven::extract_features(status, h, bytes_span(body), elapsed_ms);
        auto d = status_to_dict(r.status);
        d["status_code"]           = r.status_code;
        d["status_class"]          = r.status_class;
        d["body_size"]             = r.body_size;
        d["body_entropy"]          = r.body_entropy;
        d["printable_ratio"]       = r.printable_ratio;
        d["is_text_like"]          = r.is_text_like;
        d["is_json"]               = r.is_json;
        d["header_count"]          = r.header_count;
        d["has_content_type"]      = r.has_content_type;
        d["has_set_cookie"]        = r.has_set_cookie;
        d["has_location"]          = r.has_location;
        d["elapsed_ms"]            = r.elapsed_ms;
        d["body_similarity"]       = r.body_similarity;
        d["simhash_similarity"]    = r.simhash_similarity;
        d["exact_body_match"]      = r.exact_body_match;
        d["normalized_body_match"] = r.normalized_body_match;
        d["json_key_count"]        = r.json_key_count;
        d["json_max_depth"]        = r.json_max_depth;
        d["length_z_score"]        = r.length_z_score;
        return d;
    }, py::arg("status"), py::arg("headers"), py::arg("body"),
       py::arg("elapsed_ms") = -1LL);

    // ── Pattern scanner ──────────────────────────────────────────────────────
    py::class_<raven::PatternScanner>(m, "PatternScanner")
        .def_static("build", [](const std::vector<std::string>& patterns)
                              -> py::object {
            auto s = raven::PatternScanner::build(patterns);
            if (!s) return py::none();
            return py::cast(std::move(*s));
        }, py::arg("patterns"),
           "Build an Aho-Corasick automaton from a list of byte string patterns.")
        .def("scan", [](const raven::PatternScanner& scanner,
                        const py::bytes& data) {
            auto r = scanner.scan(bytes_span(data));
            auto d = status_to_dict(r.status);
            py::list matches;
            for (auto& m : r.matches) {
                py::dict md;
                md["offset"]     = m.offset;
                md["length"]     = m.length;
                md["pattern_id"] = m.pattern_id;
                matches.append(md);
            }
            d["matches"]   = matches;
            d["truncated"] = r.truncated;
            return d;
        }, py::arg("data"))
        .def("pattern_count", &raven::PatternScanner::pattern_count);

    // ── Decompression ────────────────────────────────────────────────────────
    m.def("decompress_gzip", [](const py::bytes& data) {
        auto r = raven::decompress(bytes_span(data), raven::CompressionFormat::GZIP);
        auto d = status_to_dict(r.status);
        d["output"]         = py::bytes(reinterpret_cast<const char*>(r.output.data()),
                                        r.output.size());
        d["input_consumed"] = r.input_consumed;
        d["expansion_ratio"] = r.expansion_ratio;
        return d;
    }, py::arg("data"));

    m.def("decompress_deflate", [](const py::bytes& data) {
        auto r = raven::decompress(bytes_span(data), raven::CompressionFormat::DEFLATE);
        auto d = status_to_dict(r.status);
        d["output"]         = py::bytes(reinterpret_cast<const char*>(r.output.data()),
                                        r.output.size());
        d["input_consumed"] = r.input_consumed;
        d["expansion_ratio"] = r.expansion_ratio;
        return d;
    }, py::arg("data"));

    // ABI version constant for Python-side rejection of mismatches
    m.attr("NATIVE_ABI_VERSION") = raven::NATIVE_ABI_VERSION;
    m.attr("NATIVE_VERSION")     = std::to_string(raven::NATIVE_VERSION_MAJOR) + "."
                                 + std::to_string(raven::NATIVE_VERSION_MINOR) + "."
                                 + std::to_string(raven::NATIVE_VERSION_PATCH);
}
