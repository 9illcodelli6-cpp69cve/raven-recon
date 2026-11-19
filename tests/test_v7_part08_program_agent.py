"""RAVEN V7 Part 08 — Program Agent Tests."""
import sqlite3
import pytest


def fresh_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db


# ── Program Policy ────────────────────────────────────────────────────────────

class TestProgramPolicy:
    def test_external_targets_always_zero(self):
        from raven.program_agent.policy import ProgramPolicy
        p = ProgramPolicy(program_id="p1", name="Test", external_targets=99)
        assert p.external_targets == 0

    def test_external_targets_immutable(self):
        from raven.program_agent.policy import ProgramPolicy
        p = ProgramPolicy(program_id="p1", name="Test")
        with pytest.raises(AttributeError):
            p.external_targets = 1

    def test_scope_in_scope(self):
        from raven.program_agent.policy import ProgramPolicy, ProgramScope, ScopeType
        scope = ProgramScope()
        scope.add_in_scope("example.com")
        p = ProgramPolicy(program_id="p1", name="Test", scope=scope)
        assert p.is_target_allowed("https://example.com/api/v1")
        assert not p.is_target_allowed("https://evil.com")

    def test_out_of_scope_exclusion(self):
        from raven.program_agent.policy import ProgramPolicy, ProgramScope
        scope = ProgramScope()
        scope.add_in_scope("example.com")
        scope.add_out_of_scope("internal.example.com")
        p = ProgramPolicy(program_id="p1", name="Test", scope=scope)
        assert not p.is_target_allowed("https://internal.example.com/admin")
        assert p.is_target_allowed("https://www.example.com")

    def test_to_dict(self):
        from raven.program_agent.policy import ProgramPolicy
        p = ProgramPolicy(program_id="p1", name="Test Program", platform="bugcrowd")
        d = p.to_dict()
        assert d["external_targets"] == 0


# ── Scope Item ────────────────────────────────────────────────────────────────

class TestScopeItem:
    def test_wildcard_matches_subdomain(self):
        from raven.program_agent.policy import ScopeItem, ScopeType
        item = ScopeItem(value="*.example.com", scope_type=ScopeType.WILDCARD)
        assert item.matches("https://api.example.com/v1")
        assert not item.matches("https://evil.com")

    def test_exact_domain_match(self):
        from raven.program_agent.policy import ScopeItem, ScopeType
        item = ScopeItem(value="example.com", scope_type=ScopeType.DOMAIN)
        assert item.matches("https://example.com/path")


# ── Program Store ─────────────────────────────────────────────────────────────

class TestProgramStore:
    def test_save_and_list(self):
        from raven.program_agent.program import ProgramStore, BugBountyProgram
        from raven.program_agent.policy import ProgramPolicy
        store = ProgramStore(db=fresh_db())
        prog = BugBountyProgram(
            workspace_id="ws1",
            policy=ProgramPolicy(program_id="p1", name="Test"),
        )
        store.save(prog)
        active = store.list_active(workspace_id="ws1")
        assert len(active) == 1

    def test_count(self):
        from raven.program_agent.program import ProgramStore, BugBountyProgram
        store = ProgramStore(db=fresh_db())
        for i in range(3):
            store.save(BugBountyProgram(workspace_id="ws1"))
        assert store.count(workspace_id="ws1") == 3


# ── Submission Store ──────────────────────────────────────────────────────────

class TestSubmissionStore:
    def test_save_and_list(self):
        from raven.program_agent.submission import SubmissionStore, Submission
        store = SubmissionStore(db=fresh_db())
        sub = Submission(
            program_id="p1",
            finding_id="f1",
            title="IDOR via /api/users/{id}",
            severity="HIGH",
        )
        store.save(sub)
        subs = store.list_for_program("p1")
        assert len(subs) == 1
        assert subs[0].title == "IDOR via /api/users/{id}"

    def test_human_reviewed_flag(self):
        from raven.program_agent.submission import Submission, SubmissionStatus
        sub = Submission(program_id="p1", human_reviewed=False)
        assert sub.status == SubmissionStatus.DRAFT
        assert not sub.human_reviewed    # must be explicitly set

    def test_count(self):
        from raven.program_agent.submission import SubmissionStore, Submission
        store = SubmissionStore(db=fresh_db())
        store.save(Submission(program_id="p1", workspace_id="ws1"))
        store.save(Submission(program_id="p2", workspace_id="ws1"))
        assert store.count(workspace_id="ws1") == 2


# ── Tool Registration ─────────────────────────────────────────────────────────

class TestProgramToolRegistration:
    def test_register_program_tools(self):
        from raven.program_agent.registry import register_program_tools
        from raven.runtime.tools import ToolRegistry
        registry = ToolRegistry()
        count = register_program_tools(registry)
        assert count >= 4
        ids = [t.tool_id for t in registry.list_all()]
        assert "program.policy.check" in ids
        assert "program.submission.create" in ids
