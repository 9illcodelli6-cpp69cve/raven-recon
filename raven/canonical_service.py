"""V5 Canonical Service Layer.

Orchestrates Stage 1-11 components against the actual runtime.
Connects RAVEN's controlled HTTP execution path to canonical
persistence, response analysis, baseline tracking, candidate
generation, and evidence graph construction.

Security invariants:
- All target traffic must originate through RAVEN's controlled path.
- verification_status always starts as 'unverified'.
- Candidate findings are hypotheses, never automatic confirmations.
- Evidence is INSERT-only; this service never mutates stored evidence.
- Baseline updates require BaselineEligibilityPolicy approval.
- No network I/O in this module; it only transforms and persists.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from .baseline_engine import (
    BaselineEligibilityPolicy,
    ObservationEligibility,
    update_baseline as _update_baseline,
)
from .evidence_graph import EvidenceGraph, EvidenceGraphError
from .finding_generator import CandidateFindingGenerator
from .response_analysis import ResponseRepr

SOURCE_ENGINE = "RAVEN"
SOURCE_VERSION = "5.0.1"

_ELIGIBILITY_POLICY = BaselineEligibilityPolicy()
_FINDING_GEN = CandidateFindingGenerator()


def _uid() -> str:
    return uuid.uuid4().hex


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class CanonicalService:
    """Thin orchestration layer: no network transport, no UI logic.

    Each public method is safe to call from the request handler thread.
    A failure inside this service must never interrupt the HTTP response
    to the client — all methods catch and suppress internal exceptions.
    """

    def __init__(self, store, workspace_id: str, workspace_name: str = "default"):
        self._store = store
        self._workspace_id = workspace_id
        store.ensure_workspace_record(workspace_id, workspace_name)

    # ------------------------------------------------------------------
    # Observation capture (V5-04, V5-05)
    # ------------------------------------------------------------------

    def record_send_result(
        self,
        result: dict,
        *,
        url: str,
        method: str,
        request_headers: dict = None,
        request_body: str = "",
        identity_label: str = "manual",
        acquisition_mode: str = "collect",
        is_probe: bool = False,
        is_anomalous: bool = False,
        baseline_approved: bool = False,
        run_id=None,
        job_id=None,
        asset_id: str = None,
    ) -> str | None:
        """Persist a controlled HTTP exchange as a canonical Observation.

        Returns observation_id or None if blocked/error/persistence failure.
        """
        if not result.get("ok"):
            return None
        try:
            obs_id = _uid()
            safe_req_headers = {
                k: v for k, v in (request_headers or {}).items()
                if k.lower() not in (
                    "authorization", "cookie", "set-cookie",
                    "proxy-authorization", "x-raven-token",
                )
            }
            resp_headers = result.get("headers") or {}
            safe_resp_headers = {
                k: v for k, v in resp_headers.items()
                if k.lower() not in ("set-cookie",)
            }
            body = result.get("body", "") or ""
            body_hash = result.get("raw_sha256") or _sha256(body)

            obs = {
                "id": obs_id,
                "workspace_id": self._workspace_id,
                "asset_id": asset_id,
                "run_id": str(run_id) if run_id is not None else None,
                "job_id": str(job_id) if job_id is not None else None,
                "url": url,
                "method": method.upper(),
                "request_headers": json.dumps(safe_req_headers, ensure_ascii=False),
                "request_body_hash": _sha256(request_body) if request_body else None,
                "request_body_len": len(request_body.encode("utf-8")) if request_body else 0,
                "status": result.get("status"),
                "response_headers": json.dumps(safe_resp_headers, ensure_ascii=False),
                "response_body_len": result.get("bytes", 0),
                "response_body_hash": body_hash,
                "elapsed_ms": result.get("elapsed_ms", 0),
                "identity_label": identity_label,
                "source_engine": SOURCE_ENGINE,
                "source_version": SOURCE_VERSION,
                "timestamp": _now(),
                "truncated": int(bool(result.get("truncated"))),
                "decode_lossy": int(bool(result.get("decode_lossy"))),
                "acquisition_mode": acquisition_mode,
                "is_probe": int(is_probe),
                "is_anomalous": int(is_anomalous),
                "baseline_approved": int(baseline_approved),
            }
            self._store.save_observation(obs)
            return obs_id
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Evidence (V5-05)
    # ------------------------------------------------------------------

    def record_evidence(
        self,
        kind: str,
        summary: str,
        *,
        finding_id: str = None,
        observation_id: str = None,
        raw: str = None,
    ) -> str | None:
        """Persist an Evidence row (INSERT-only). Returns evidence_id or None."""
        try:
            ev_id = _uid()
            ev = {
                "id": ev_id,
                "workspace_id": self._workspace_id,
                "finding_id": finding_id,
                "observation_id": observation_id,
                "kind": kind,
                "raw": raw,
                "summary": summary,
                "source_engine": SOURCE_ENGINE,
                "source_version": SOURCE_VERSION,
                "timestamp": _now(),
            }
            self._store.save_evidence(ev)
            return ev_id
        except Exception:
            return None

    def record_note_evidence(
        self,
        summary: str,
        *,
        observation_id: str = None,
        finding_id: str = None,
        actor: str = "RESEARCHER",
    ) -> str | None:
        """Record a free-text NOTE evidence row (researcher/agent annotation).

        Convenience over ``record_evidence`` with ``kind="note"``. The write is
        INSERT-only and ADVISORY: a note is never a verdict and never changes any
        finding's verification/review status — only ``ReviewWorkflow`` (human,
        non-automated) can do that (see ``submit_review``).

        Actor provenance (RESEARCHER / RAVEN_AGENT / PROGRAM_AGENT / SYSTEM) is
        stamped into the EXISTING ``raw`` column as a small JSON blob, so no
        ``recon.db`` schema change (no ADD COLUMN) is required to carry it.
        Returns evidence_id or None.
        """
        actor_name = getattr(actor, "value", actor) or "SYSTEM"
        try:
            raw = json.dumps({"actor": str(actor_name), "provenance": "note"})
        except Exception:
            raw = None
        return self.record_evidence(
            "note", summary,
            finding_id=finding_id, observation_id=observation_id, raw=raw,
        )

    # ------------------------------------------------------------------
    # Candidate findings (V5-13, V5-08, V5-09)
    # ------------------------------------------------------------------

    def create_candidate_access_control(
        self,
        url: str,
        owner_result: dict,
        other_result: dict,
        *,
        other_label: str,
        verdict: str,
        owner_obs_id: str = None,
        other_obs_id: str = None,
        asset_id: str = None,
    ) -> str | None:
        """Create a candidate finding from access-check comparison.

        Only creates for INCONSISTENT verdicts. All candidates start unverified.
        An INCONSISTENT verdict is a hypothesis — not a confirmed vulnerability.
        HTTP 200 != BOLA/IDOR. Researcher verification is required.
        """
        if verdict != "INCONSISTENT":
            return None
        try:
            candidate = _FINDING_GEN.generate(
                workspace_id=self._workspace_id,
                title=f"Possible access control difference: {other_label} vs owner at {url}",
                url=url,
                severity="info",
                observation_id=owner_obs_id,
                asset_id=asset_id,
                description=(
                    f"Owner ({owner_result.get('status')}) vs "
                    f"{other_label} ({other_result.get('status')}). "
                    f"Verdict: {verdict}. "
                    "This is an unverified candidate — manual researcher confirmation required. "
                    "A matching response is not proof of an authorization flaw."
                ),
            )
            row = _FINDING_GEN.to_db_row(candidate)
            self._store.save_finding(row)
            # Evidence records
            if owner_obs_id:
                self.record_evidence(
                    "access_control_comparison",
                    f"Owner response status={owner_result.get('status')} (obs {owner_obs_id})",
                    finding_id=candidate.id,
                    observation_id=owner_obs_id,
                )
            if other_obs_id:
                self.record_evidence(
                    "access_control_comparison",
                    f"{other_label} response status={other_result.get('status')}: verdict={verdict}",
                    finding_id=candidate.id,
                    observation_id=other_obs_id,
                )
            # Evidence graph link
            self._link_observation_to_finding(candidate.id, owner_obs_id)
            self._link_observation_to_finding(candidate.id, other_obs_id)
            return candidate.id
        except Exception:
            return None

    def create_candidate_agent_finding(self, title: str, url: str, severity: str,
                                       description: str, evidence: str) -> str | None:
        """A candidate proposed by the Claude agent. Always unverified — the operator's
        review decides; the evidence text the agent captured is stored with it."""
        try:
            candidate = _FINDING_GEN.generate(
                workspace_id=self._workspace_id,
                title=f"[Claude agent] {title}"[:300],
                url=url,
                severity=severity if severity in ("info", "low", "medium", "high", "critical") else "info",
                description=(description + "\n\nProposed by the Claude agent — unverified; confirm it "
                             "manually before reporting.")[:9000],
            )
            self._store.save_finding(_FINDING_GEN.to_db_row(candidate))
            if evidence:
                self.record_evidence("agent_evidence", evidence[:20000], finding_id=candidate.id)
            return candidate.id
        except Exception:
            return None

    def create_candidate_xss_reflection(
        self,
        url: str,
        context: str,
        *,
        observation_id: str = None,
        asset_id: str = None,
    ) -> str | None:
        """Create a candidate finding from XSS canary reflection.

        Reflection is NOT proof of execution. Finding starts unverified.
        Researcher must manually confirm executable context.
        """
        try:
            candidate = _FINDING_GEN.generate(
                workspace_id=self._workspace_id,
                title=f"XSS canary reflected ({context} context) — unverified",
                url=url,
                severity="info",
                observation_id=observation_id,
                asset_id=asset_id,
                description=(
                    f"Canary reflected in {context} context at {url}. "
                    "Reflection alone is NOT proof of XSS execution. "
                    "Manual researcher verification required to establish exploitability."
                ),
            )
            row = _FINDING_GEN.to_db_row(candidate)
            self._store.save_finding(row)
            if observation_id:
                self.record_evidence(
                    "xss_reflection",
                    f"XSS canary reflected in {context} context at {url}",
                    finding_id=candidate.id,
                    observation_id=observation_id,
                )
                self._link_observation_to_finding(candidate.id, observation_id)
            return candidate.id
        except Exception:
            return None

    def _link_observation_to_finding(self, finding_id: str, obs_id: str) -> None:
        """V5-15: use EvidenceGraph to validate and build the edge, then persist."""
        if not finding_id or not obs_id:
            return
        try:
            graph = EvidenceGraph(self._workspace_id)
            graph.add_node(obs_id, "observation")
            graph.add_node(finding_id, "finding")
            edge = graph.add_edge(
                from_id=obs_id, from_type="observation",
                to_id=finding_id, to_type="finding",
                relation="supports", confidence=1.0,
                source=SOURCE_ENGINE,
            )
            rel = graph.edge_to_db_row(edge)
            self._store.save_relationship(rel)
        except (EvidenceGraphError, Exception):
            pass

    def record_graph_edge(
        self,
        from_id: str,
        from_type: str,
        to_id: str,
        to_type: str,
        relation: str,
        confidence: float = 1.0,
    ) -> str | None:
        """Validate and persist a graph edge using EvidenceGraph. Returns edge id or None."""
        try:
            graph = EvidenceGraph(self._workspace_id)
            graph.add_node(from_id, from_type)
            graph.add_node(to_id, to_type)
            edge = graph.add_edge(
                from_id=from_id, from_type=from_type,
                to_id=to_id, to_type=to_type,
                relation=relation, confidence=confidence,
                source=SOURCE_ENGINE,
            )
            rel = graph.edge_to_db_row(edge)
            self._store.save_relationship(rel)
            return edge.id
        except (EvidenceGraphError, Exception):
            return None

    # ------------------------------------------------------------------
    # Review workflow (V5-14)
    # ------------------------------------------------------------------

    def submit_review(
        self,
        finding_id: str,
        action: str,
        *,
        actor: str = "researcher",
        note: str = None,
    ) -> dict:
        """Transition a finding's review state. Only the researcher may confirm.

        When a researcher confirms a finding (action='confirmed'), a ground-truth
        label is written to labeled_observations for dataset construction (Task B:
        authorization_significance).  Only human review creates these labels —
        no automated path reaches this branch.
        """
        from .review_workflow import ReviewWorkflow, FindingReviewState, WorkflowError

        finding = self._store.get_finding(finding_id, self._workspace_id)
        if not finding:
            return {"error": "finding not found"}
        try:
            wf = ReviewWorkflow()
            state = FindingReviewState(
                finding_id=finding_id,
                review_status=finding.get("review_status", "new"),
                verification_status=finding.get("verification_status", "unverified"),
            )
            event = wf.transition(state, action, actor=actor, is_automated=False, note=note)
            row = wf.event_to_db_row(event)
            self._store.save_review_event(row)
            self._store.update_finding(finding_id, self._workspace_id, {
                "review_status": state.review_status,
                "verification_status": state.verification_status,
                "updated_at": _now(),
            })
            # V5 Task 2: researcher confirmation creates a human ground-truth label.
            # Only 'confirmed' → 'verified' transitions produce a real label.
            # Dismissed/rejected findings produce a 'negative' label so the dataset
            # reflects researcher judgment for both positive and negative examples.
            if action in ("confirmed", "dismissed"):
                try:
                    from .dataset_foundation import LabelStore, TASK_B
                    ls = LabelStore()
                    label_value = "positive" if action == "confirmed" else "negative"
                    labeled = ls.write_label(
                        workspace_id=self._workspace_id,
                        task=TASK_B,
                        label=label_value,
                        labeler=actor or "researcher",
                        observation_id=finding.get("observation_id"),
                        asset_id=finding.get("asset_id") or "",
                        note=note or "",
                        synthetic=False,
                    )
                    self._store.save_labeled_observation(ls.to_db_row(labeled))
                except Exception:
                    pass  # label persistence failure must not break the review response
            return {
                "ok": True,
                "review_status": state.review_status,
                "verification_status": state.verification_status,
                "event_id": event.id,
            }
        except Exception as exc:
            return {"error": str(exc)}

    # ------------------------------------------------------------------
    # Baseline (V5-07)
    # ------------------------------------------------------------------

    def maybe_update_baseline(
        self,
        result: dict,
        *,
        asset_id: str,
        url_fingerprint: str,
        identity_label: str,
        acquisition_mode: str = "collect",
        is_probe: bool = False,
        is_anomalous: bool = False,
        baseline_approved: bool = False,
    ) -> None:
        """Update baseline statistics if this observation is eligible.

        Silently skips ineligible observations — probe traffic cannot
        contaminate baselines through this path.
        """
        eligibility = ObservationEligibility(
            acquisition_mode=acquisition_mode,
            is_probe=is_probe,
            is_anomalous=is_anomalous,
            baseline_approved=baseline_approved,
        )
        if not _ELIGIBILITY_POLICY.is_eligible(eligibility):
            return
        if not result.get("ok"):
            return
        try:
            body = result.get("body", "") or ""
            resp_headers = result.get("headers") or {}
            obs_repr = ResponseRepr.from_raw(
                status=result.get("status", 200),
                raw_headers=resp_headers,
                raw_body=body.encode("utf-8", "replace"),
                elapsed_ms=result.get("elapsed_ms", 0),
                identity_label=identity_label,
                acquisition_mode=acquisition_mode,
            )
            existing = self._store.get_baseline(
                self._workspace_id, asset_id, url_fingerprint, identity_label
            )
            if existing:
                baseline = dict(existing)
            else:
                baseline = {
                    "id": _uid(),
                    "workspace_id": self._workspace_id,
                    "asset_id": asset_id,
                    "url_fingerprint": url_fingerprint,
                    "identity_label": identity_label,
                    "sample_count": 0,
                    "body_len_mean": 0.0,
                    "body_len_m2": 0.0,
                    "timing_mean": 0.0,
                    "timing_m2": 0.0,
                    "status_counts": "{}",
                    "header_fp_counts": "{}",
                    "last_sample_at": None,
                    "created_at": _now(),
                }
            updated = _update_baseline(baseline, obs_repr)
            updated["updated_at"] = _now()
            updated["last_sample_at"] = _now()
            self._store.save_baseline(updated)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # ML readiness (V5-18)
    # ------------------------------------------------------------------

    def ml_readiness_status(self) -> dict:
        """Return current ML readiness. Never trains a model."""
        try:
            from .ml_readiness import ReadinessChecker
            from .dataset_foundation import TASK_A
            checker = ReadinessChecker()
            report = checker.evaluate_readiness(TASK_A, labeled_rows=None)
            # ReadinessReport carries `reasons` (+ an optional gate snapshot); it never
            # had `blockers`/`notes`, so this used to surface an AttributeError string
            # as the only "blocker".
            snap = getattr(report, "gate_snapshot", None)
            notes = []
            if snap is not None:
                notes.append(f"{snap.row_count} rows · {snap.positive_count} positive · "
                             f"{snap.negative_count} negative · {snap.unique_groups} groups")
            return {
                "status": report.status.value,
                "model_trained": report.model_trained,
                "ml_probability_modified": report.ml_probability_modified,
                "blockers": list(report.reasons),
                "notes": notes,
            }
        except Exception as exc:
            return {
                "status": "not_ready_for_training",
                "model_trained": False,
                "ml_probability_modified": False,
                "blockers": [str(exc)],
                "notes": [],
            }

    # ------------------------------------------------------------------
    # Reporting (V5-16)
    # ------------------------------------------------------------------

    def generate_finding_report(self, finding_id: str) -> dict:
        """Generate an evidence-grounded Markdown report for a finding."""
        try:
            from .reporting import ReportGenerator, ReportingError
            finding = self._store.get_finding(finding_id, self._workspace_id)
            if not finding:
                return {"error": "finding not found"}
            evidence_rows = self._store.get_evidence(finding_id, self._workspace_id)
            gen = ReportGenerator()
            report = gen.build_finding_report(finding, evidence_rows=evidence_rows)
            md = gen.to_markdown(report)
            return {"ok": True, "markdown": md, "finding_id": finding_id}
        except Exception as exc:
            return {"error": str(exc)}
