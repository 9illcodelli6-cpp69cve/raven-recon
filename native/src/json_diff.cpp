/**
 * RAVEN Native — JSON structural diff (Phase 15).
 *
 * Uses a minimal recursive-descent JSON parser.
 * Protected against: deep recursion (MAX_JSON_DEPTH), huge structures
 * (MAX_JSON_KEYS), and malformed input.
 *
 * Returns structural differences only — no security verdict.
 */
#include "raven_native.h"
#include <charconv>
#include <cstring>    // std::memcmp (GCC/Clang need it explicitly)
#include <optional>
#include <variant>

namespace raven {

// ─── Minimal JSON value representation ───────────────────────────────────────

struct JsonValue;
using JsonNull    = std::monostate;
using JsonBool    = bool;
using JsonNumber  = double;
using JsonString  = std::string;
using JsonArray   = std::vector<JsonValue>;
using JsonObject  = std::vector<std::pair<std::string, JsonValue>>;

struct JsonValue : std::variant<JsonNull, JsonBool, JsonNumber, JsonString,
                                JsonArray, JsonObject> {
    using variant::variant;
};

static const char* type_name(const JsonValue& v) noexcept {
    return std::visit([](auto&& x) -> const char* {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, JsonNull>)   return "null";
        if constexpr (std::is_same_v<T, JsonBool>)   return "boolean";
        if constexpr (std::is_same_v<T, JsonNumber>)  return "number";
        if constexpr (std::is_same_v<T, JsonString>)  return "string";
        if constexpr (std::is_same_v<T, JsonArray>)   return "array";
        if constexpr (std::is_same_v<T, JsonObject>)  return "object";
        return "unknown";
    }, v);
}

// ─── Parser ──────────────────────────────────────────────────────────────────

struct ParseCtx {
    const char* p;
    const char* end;
    int depth = 0;
    size_t key_count = 0;
    bool truncated = false;

    void skip_ws() noexcept {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
            ++p;
    }

    bool expect(char c) noexcept { if (p < end && *p == c) { ++p; return true; } return false; }
    char peek() const noexcept   { return p < end ? *p : '\0'; }
    bool at_end() const noexcept { return p >= end; }
};

static std::optional<JsonValue> parse_value(ParseCtx& ctx);

static std::optional<std::string> parse_string(ParseCtx& ctx) {
    if (!ctx.expect('"')) return std::nullopt;
    std::string s;
    while (ctx.p < ctx.end && *ctx.p != '"') {
        if (*ctx.p == '\\') {
            ++ctx.p;
            if (ctx.p >= ctx.end) return std::nullopt;
            switch (*ctx.p) {
                case '"': case '\\': case '/': s += *ctx.p; break;
                case 'n': s += '\n'; break;
                case 't': s += '\t'; break;
                case 'r': s += '\r'; break;
                default: s += '\\'; s += *ctx.p;
            }
        } else {
            s += *ctx.p;
        }
        ++ctx.p;
    }
    if (!ctx.expect('"')) return std::nullopt;
    return s;
}

static std::optional<JsonValue> parse_value(ParseCtx& ctx) {
    if (ctx.depth > static_cast<int>(MAX_JSON_DEPTH))
        return std::nullopt;
    if (ctx.key_count > MAX_JSON_KEYS) {
        ctx.truncated = true;
        return std::nullopt;
    }

    ctx.skip_ws();
    if (ctx.at_end()) return std::nullopt;

    char c = ctx.peek();

    if (c == '"') {
        auto s = parse_string(ctx);
        if (!s) return std::nullopt;
        return JsonValue{std::move(*s)};
    }
    if (c == '{') {
        ++ctx.p; ++ctx.depth;
        JsonObject obj;
        ctx.skip_ws();
        if (ctx.peek() == '}') { ++ctx.p; --ctx.depth; return JsonValue{std::move(obj)}; }
        while (true) {
            ctx.skip_ws();
            auto key = parse_string(ctx);
            if (!key) return std::nullopt;
            ctx.skip_ws();
            if (!ctx.expect(':')) return std::nullopt;
            ++ctx.key_count;
            auto val = parse_value(ctx);
            if (!val) return std::nullopt;
            obj.push_back({std::move(*key), std::move(*val)});
            ctx.skip_ws();
            if (ctx.peek() == '}') { ++ctx.p; --ctx.depth; return JsonValue{std::move(obj)}; }
            if (!ctx.expect(',')) return std::nullopt;
        }
    }
    if (c == '[') {
        ++ctx.p; ++ctx.depth;
        JsonArray arr;
        ctx.skip_ws();
        if (ctx.peek() == ']') { ++ctx.p; --ctx.depth; return JsonValue{std::move(arr)}; }
        while (true) {
            auto val = parse_value(ctx);
            if (!val) return std::nullopt;
            arr.push_back(std::move(*val));
            ctx.skip_ws();
            if (ctx.peek() == ']') { ++ctx.p; --ctx.depth; return JsonValue{std::move(arr)}; }
            if (!ctx.expect(',')) return std::nullopt;
        }
    }
    if (c == 't' && ctx.end - ctx.p >= 4 && std::memcmp(ctx.p, "true", 4) == 0) {
        ctx.p += 4; return JsonValue{true};
    }
    if (c == 'f' && ctx.end - ctx.p >= 5 && std::memcmp(ctx.p, "false", 5) == 0) {
        ctx.p += 5; return JsonValue{false};
    }
    if (c == 'n' && ctx.end - ctx.p >= 4 && std::memcmp(ctx.p, "null", 4) == 0) {
        ctx.p += 4; return JsonValue{JsonNull{}};
    }
    // Try number
    if (c == '-' || (c >= '0' && c <= '9')) {
        double d = 0.0;
        auto [endp, ec] = std::from_chars(ctx.p, ctx.end, d);
        if (ec == std::errc{}) { ctx.p = endp; return JsonValue{d}; }
    }
    return std::nullopt;
}

// ─── Diff ─────────────────────────────────────────────────────────────────────

static void diff_values(const JsonValue& a, const JsonValue& b,
                         const std::string& path,
                         std::vector<JsonDiffEntry>& out,
                         bool& truncated) noexcept {
    if (out.size() >= MAX_JSON_KEYS) { truncated = true; return; }

    if (a.index() != b.index()) {
        out.push_back({path, "type_changed", type_name(a), type_name(b)});
        return;
    }

    if (std::holds_alternative<JsonObject>(a)) {
        const auto& oa = std::get<JsonObject>(a);
        const auto& ob = std::get<JsonObject>(b);
        // Build quick lookup
        std::unordered_map<std::string, const JsonValue*> mb;
        for (const auto& [k, v] : ob) mb[k] = &v;
        std::unordered_map<std::string, const JsonValue*> ma;
        for (const auto& [k, v] : oa) ma[k] = &v;

        for (const auto& [k, va] : oa) {
            std::string sub = path + "." + k;
            auto it = mb.find(k);
            if (it == mb.end()) out.push_back({sub, "removed", type_name(va), ""});
            else diff_values(va, *it->second, sub, out, truncated);
        }
        for (const auto& [k, vb] : ob) {
            if (ma.find(k) == ma.end())
                out.push_back({path + "." + k, "added", "", type_name(vb)});
        }
        return;
    }

    if (std::holds_alternative<JsonArray>(a)) {
        const auto& aa = std::get<JsonArray>(a);
        const auto& ab = std::get<JsonArray>(b);
        size_t limit = std::min(aa.size(), ab.size());
        for (size_t i = 0; i < limit; ++i) {
            diff_values(aa[i], ab[i], path + "[" + std::to_string(i) + "]", out, truncated);
        }
        if (aa.size() != ab.size())
            out.push_back({path, "array_length_changed",
                          std::to_string(aa.size()), std::to_string(ab.size())});
        return;
    }

    // Scalar compare
    bool equal = std::visit([&](const auto& va) {
        using T = std::decay_t<decltype(va)>;
        if (!std::holds_alternative<T>(b)) return false;
        return va == std::get<T>(b);
    }, a);

    if (!equal)
        out.push_back({path, "changed", type_name(a), type_name(b)});
}

static size_t count_keys(const JsonValue& v) noexcept {
    if (std::holds_alternative<JsonObject>(v)) {
        size_t n = 0;
        for (const auto& [k, sub] : std::get<JsonObject>(v))
            n += 1 + count_keys(sub);
        return n;
    }
    if (std::holds_alternative<JsonArray>(v)) {
        size_t n = 0;
        for (const auto& sub : std::get<JsonArray>(v))
            n += count_keys(sub);
        return n;
    }
    return 0;
}

JsonDiffResult diff_json(std::span<const uint8_t> a,
                          std::span<const uint8_t> b) noexcept {
    if (a.size() > MAX_BODY_BYTES || b.size() > MAX_BODY_BYTES)
        return {Status::INPUT_TOO_LARGE};

    ParseCtx ca{reinterpret_cast<const char*>(a.data()),
                reinterpret_cast<const char*>(a.data()) + a.size()};
    ParseCtx cb{reinterpret_cast<const char*>(b.data()),
                reinterpret_cast<const char*>(b.data()) + b.size()};

    auto va = parse_value(ca);
    auto vb = parse_value(cb);

    if (!va || !vb)
        return {Status::MALFORMED, false, {}, 0, 0, false};

    JsonDiffResult r{};
    r.status       = Status::OK;
    r.total_keys_a = count_keys(*va);
    r.total_keys_b = count_keys(*vb);
    r.truncated    = ca.truncated || cb.truncated;

    bool trunc = false;
    diff_values(*va, *vb, "$", r.differences, trunc);
    r.truncated = r.truncated || trunc;
    r.are_equal = r.differences.empty();

    return r;
}

} // namespace raven
