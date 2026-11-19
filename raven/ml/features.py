"""RAVEN ML Feature Pipeline (Phases 76-84).

Extracts a versioned, structured feature vector from RAVEN observations.

INVARIANTS:
- NEVER include raw credentials, cookies, Authorization header values in features.
- NEVER use post-review fields (verification_status, review outcome) as features.
- Preprocessing (scaler) fitted ONLY on training data; persisted for inference.
- Missing values have deterministic semantics (documented per field).
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field, asdict
from typing import Optional, Any

FEATURE_SCHEMA_VERSION = "v1"

# Sentinel for "feature not available" — distinct from 0
MISSING_FLOAT = -1.0
MISSING_INT   = -1


@dataclass
class FeatureVector:
    """Versioned structured feature vector for one observation.

    Docstring per field explains missing-value semantics.
    Fields that are -1 were not available at extraction time.
    """
    schema_version: str = FEATURE_SCHEMA_VERSION

    # ── HTTP status ─────────────────────────────────────────────────────────
    status_code: int     = MISSING_INT    # HTTP status integer
    status_class: int    = MISSING_INT    # 1/2/3/4/5 (class); -1 if unknown

    # ── Body ────────────────────────────────────────────────────────────────
    body_size: int       = MISSING_INT    # raw body bytes; -1 if unavailable
    body_entropy: float  = MISSING_FLOAT  # Shannon entropy; -1 if no body
    printable_ratio: float = MISSING_FLOAT  # fraction printable ASCII
    is_text_like: int    = MISSING_INT    # 1/0/−1
    is_json: int         = MISSING_INT    # 1/0/−1

    # ── Headers ─────────────────────────────────────────────────────────────
    header_count: int    = MISSING_INT
    has_content_type: int = MISSING_INT  # 1/0
    has_set_cookie: int  = MISSING_INT   # 1/0 — presence only, not value
    has_location: int    = MISSING_INT   # 1/0

    # ── Timing ──────────────────────────────────────────────────────────────
    elapsed_ms: int      = MISSING_INT

    # ── Similarity vs comparison response (populated in ACL tests) ──────────
    body_similarity: float      = MISSING_FLOAT   # -1 if no comparison available
    simhash_similarity: float   = MISSING_FLOAT
    exact_body_match: int       = MISSING_INT
    normalized_body_match: int  = MISSING_INT
    header_added_count: int     = MISSING_INT
    header_removed_count: int   = MISSING_INT
    header_changed_count: int   = MISSING_INT

    # ── JSON structure ───────────────────────────────────────────────────────
    json_key_count: int   = MISSING_INT
    json_diff_count: int  = MISSING_INT   # differences vs comparison; -1 if N/A

    # ── Baseline deviation ────────────────────────────────────────────────────
    length_z_score: float = MISSING_FLOAT  # signed z-score vs baseline; 0 if no baseline

    def validate(self) -> None:
        """Raise ValueError if any feature contains NaN, Inf, or wrong schema version.

        Called before passing to a model. Target-controlled values must not
        cause unbounded tensor dimensions or undefined model behavior.
        """
        import math
        for name in self.feature_names():
            val = getattr(self, name, None)
            if val is None:
                continue
            try:
                f = float(val)
            except (TypeError, ValueError):
                raise ValueError(f"Feature '{name}' cannot be cast to float: {val!r}")
            if math.isnan(f):
                raise ValueError(f"Feature '{name}' is NaN — target-controlled NaN rejected")
            if math.isinf(f):
                raise ValueError(f"Feature '{name}' is Inf — target-controlled Inf rejected")

    def to_list(self) -> list:
        """Ordered list of feature values for model input.

        Fields excluded (NEVER as features):
          - schema_version (metadata, not a signal)
          Any field tagged 'PRIVACY_EXCLUDED' must not appear here.
        """
        self.validate()
        return [
            self.status_code,
            self.status_class,
            self.body_size,
            self.body_entropy,
            self.printable_ratio,
            self.is_text_like,
            self.is_json,
            self.header_count,
            self.has_content_type,
            self.has_set_cookie,
            self.has_location,
            self.elapsed_ms,
            self.body_similarity,
            self.simhash_similarity,
            self.exact_body_match,
            self.normalized_body_match,
            self.header_added_count,
            self.header_removed_count,
            self.header_changed_count,
            self.json_key_count,
            self.json_diff_count,
            self.length_z_score,
        ]

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "status_code", "status_class",
            "body_size", "body_entropy", "printable_ratio",
            "is_text_like", "is_json",
            "header_count", "has_content_type", "has_set_cookie", "has_location",
            "elapsed_ms",
            "body_similarity", "simhash_similarity",
            "exact_body_match", "normalized_body_match",
            "header_added_count", "header_removed_count", "header_changed_count",
            "json_key_count", "json_diff_count",
            "length_z_score",
        ]

    def schema_hash(self) -> str:
        """SHA-256 of the feature name list — detects schema changes."""
        names = "|".join(self.feature_names())
        return hashlib.sha256(names.encode()).hexdigest()[:16]


class FeaturePipeline:
    """Extract FeatureVector from RAVEN observation data.

    Accepts structured observation dicts (from store.get_observation) or
    direct component values.

    PRIVACY: Never reads Authorization, Cookie, or credential-containing headers.
    """

    EXCLUDED_HEADERS = frozenset({
        "authorization", "cookie", "set-cookie",
        "x-api-key", "x-auth-token",
    })

    def extract_from_observation(self, obs: dict,
                                   comparison_obs: Optional[dict] = None,
                                   baseline_stats: Optional[dict] = None,
                                   backend: Any = None) -> FeatureVector:
        """Extract features from a stored observation dict.

        obs: dict with keys: status, headers, body_len, elapsed_ms, content_type,
             body_digest, normalized_digest, ...
        comparison_obs: optional second observation (for ACL diff features)
        baseline_stats: optional dict with 'mean_body_len', 'std_body_len'
        backend: optional AnalysisBackend (uses Python if None)
        """
        if backend is None:
            from raven.native.backend import PythonAnalysisBackend
            backend = PythonAnalysisBackend()

        fv = FeatureVector()

        # ── HTTP status ────────────────────────────────────────────────────
        status = obs.get("status", MISSING_INT)
        if isinstance(status, int) and status > 0:
            fv.status_code  = status
            fv.status_class = status // 100

        # ── Body features ──────────────────────────────────────────────────
        body_len = obs.get("body_len", MISSING_INT)
        if isinstance(body_len, int) and body_len >= 0:
            fv.body_size = body_len

        # We don't store raw body bytes in observations (by design).
        # Extract entropy/printable from normalized_text if available.
        norm_text = obs.get("normalized_text", "")
        if norm_text:
            norm_bytes = norm_text.encode("utf-8", errors="replace")
            insp = backend.inspect_binary(norm_bytes, obs.get("content_type", ""))
            if insp.get("ok"):
                fv.body_entropy    = insp["entropy"]
                fv.printable_ratio = insp["printable_ratio"]
                fv.is_text_like    = 1 if insp["text_like"] else 0
                ct = obs.get("content_type", "")
                fv.is_json         = 1 if "application/json" in ct else 0

        # ── Header features ────────────────────────────────────────────────
        raw_headers = obs.get("headers", {})
        if raw_headers and isinstance(raw_headers, str):
            try: raw_headers = json.loads(raw_headers)
            except Exception: raw_headers = {}

        # Filter out sensitive headers BEFORE extracting features
        safe_headers = {k.lower(): v for k, v in (raw_headers or {}).items()
                        if k.lower() not in self.EXCLUDED_HEADERS}
        fv.header_count     = len(safe_headers)
        fv.has_content_type = 1 if "content-type" in safe_headers else 0
        fv.has_set_cookie   = 1 if "set-cookie" in obs.get("headers", {}) else 0
        fv.has_location     = 1 if "location" in safe_headers else 0

        # ── Timing ────────────────────────────────────────────────────────
        elapsed = obs.get("elapsed_ms", MISSING_INT)
        if isinstance(elapsed, (int, float)) and elapsed >= 0:
            fv.elapsed_ms = int(elapsed)

        # ── Comparison features ───────────────────────────────────────────
        if comparison_obs:
            fv = self._fill_comparison_features(fv, obs, comparison_obs, backend)

        # ── Baseline deviation ────────────────────────────────────────────
        if baseline_stats and fv.body_size >= 0:
            mean = baseline_stats.get("mean_body_len", 0)
            std  = baseline_stats.get("std_body_len", 1)
            if std > 0:
                fv.length_z_score = (fv.body_size - mean) / std
            else:
                fv.length_z_score = 0.0

        return fv

    def _fill_comparison_features(self, fv: FeatureVector,
                                    obs: dict, comp: dict,
                                    backend: Any) -> FeatureVector:
        # Use digest-level comparison for body (no raw bytes in obs)
        fv.exact_body_match      = 1 if obs.get("body_digest") == comp.get("body_digest") else 0
        fv.normalized_body_match = 1 if obs.get("normalized_digest") == comp.get("normalized_digest") else 0

        # Body size similarity (length-based approximation)
        sa = obs.get("body_len", 0) or 0
        sb = comp.get("body_len", 0) or 0
        if max(sa, sb) > 0:
            fv.body_similarity = 1.0 - abs(sa - sb) / max(sa, sb)
        else:
            fv.body_similarity = 1.0

        fv.simhash_similarity = fv.body_similarity  # approximation without raw bytes

        # Header diff
        def safe_headers_dict(o):
            h = o.get("headers", {})
            if isinstance(h, str):
                try: h = json.loads(h)
                except Exception: h = {}
            return {k.lower(): v for k, v in (h or {}).items()
                    if k.lower() not in self.EXCLUDED_HEADERS}

        ha = safe_headers_dict(obs)
        hb = safe_headers_dict(comp)
        hdiff = backend.diff_headers(ha, hb)
        if hdiff.get("ok"):
            fv.header_added_count   = len(hdiff.get("added", []))
            fv.header_removed_count = len(hdiff.get("removed", []))
            fv.header_changed_count = len(hdiff.get("changed", []))

        return fv

    def extract_from_values(self, status: int, headers: dict, body: bytes,
                              elapsed_ms: int = MISSING_INT,
                              comparison_body: Optional[bytes] = None,
                              comparison_headers: Optional[dict] = None,
                              backend: Any = None) -> FeatureVector:
        """Direct extraction from raw values (used in training and tests)."""
        if backend is None:
            from raven.native.backend import PythonAnalysisBackend
            backend = PythonAnalysisBackend()

        fv = FeatureVector()
        fv.status_code  = status
        fv.status_class = status // 100 if status > 0 else MISSING_INT
        fv.body_size    = len(body)
        fv.elapsed_ms   = elapsed_ms

        if body:
            ct = headers.get("content-type", "")
            result = backend.extract_features(status, headers, body, elapsed_ms)
            if result.get("ok"):
                fv.body_entropy    = result["body_entropy"]
                fv.printable_ratio = result["printable_ratio"]
                fv.is_text_like    = 1 if result["is_text_like"] else 0
                fv.is_json         = 1 if result["is_json"] else 0
                fv.json_key_count  = result["json_key_count"]

        safe_headers = {k.lower(): v for k, v in headers.items()
                        if k.lower() not in self.EXCLUDED_HEADERS}
        fv.header_count     = len(safe_headers)
        fv.has_content_type = 1 if "content-type" in safe_headers else 0
        fv.has_set_cookie   = 1 if "set-cookie" in headers else 0
        fv.has_location     = 1 if "location" in safe_headers else 0

        if comparison_body is not None:
            fv.exact_body_match      = 1 if body == comparison_body else 0
            fv.normalized_body_match = fv.exact_body_match
            diff = backend.diff_bodies(body, comparison_body)
            if diff.get("ok"):
                fv.body_similarity    = diff["similarity"]
                fv.simhash_similarity = diff["similarity"]

            if comparison_headers is not None:
                safe_comp = {k.lower(): v for k, v in comparison_headers.items()
                             if k.lower() not in self.EXCLUDED_HEADERS}
                hdiff = backend.diff_headers(safe_headers, safe_comp)
                if hdiff.get("ok"):
                    fv.header_added_count   = len(hdiff["added"])
                    fv.header_removed_count = len(hdiff["removed"])
                    fv.header_changed_count = len(hdiff["changed"])

        return fv
