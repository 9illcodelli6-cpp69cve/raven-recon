"""Stage 5: Payload registry tests (Category 4).

Verifies PayloadRiskClass, PayloadDispatch safety enforcement, Payload
immutability, and that EXFILTRATION/DESTRUCTIVE payloads are always blocked.
"""
import pytest

from raven.payloads import (
    PayloadRiskClass,
    Payload,
    PayloadDispatch,
    ProbeError,
    BUILTIN_PAYLOADS,
)


class TestPayloadRiskClass:

    def test_all_classes_exist(self):
        classes = {c.value for c in PayloadRiskClass}
        assert "safe_marker" in classes
        assert "reflection_probe" in classes
        assert "header_probe" in classes
        assert "state_mutate" in classes
        assert "exfiltration" in classes
        assert "destructive" in classes

    def test_six_classes_total(self):
        assert len(PayloadRiskClass) == 6

    def test_enum_values_are_strings(self):
        for c in PayloadRiskClass:
            assert isinstance(c.value, str)


class TestPayload:

    def test_frozen_dataclass(self):
        p = Payload(
            id="test_payload",
            risk_class=PayloadRiskClass.SAFE_MARKER,
            value="test-value",
            description="test",
        )
        with pytest.raises((AttributeError, TypeError)):
            p.id = "changed"  # type: ignore[misc]

    def test_invalid_id_raises(self):
        with pytest.raises(ValueError):
            Payload(id="bad id!", risk_class=PayloadRiskClass.SAFE_MARKER,
                    value="v", description="d")

    def test_invalid_risk_class_raises(self):
        with pytest.raises(TypeError):
            Payload(id="ok_id", risk_class="not_a_class", value="v", description="d")  # type: ignore[arg-type]

    def test_tags_is_frozenset(self):
        p = Payload(id="t", risk_class=PayloadRiskClass.SAFE_MARKER,
                    value="v", description="d", tags=frozenset({"a", "b"}))
        assert isinstance(p.tags, frozenset)

    def test_default_tags_frozenset(self):
        p = Payload(id="t2", risk_class=PayloadRiskClass.SAFE_MARKER,
                    value="v", description="d")
        assert isinstance(p.tags, frozenset)
        assert len(p.tags) == 0


class TestBuiltinPayloads:

    def test_five_builtin_payloads(self):
        assert len(BUILTIN_PAYLOADS) == 5

    def test_all_safe_classes(self):
        for p in BUILTIN_PAYLOADS:
            assert p.risk_class in (
                PayloadRiskClass.SAFE_MARKER,
                PayloadRiskClass.REFLECTION_PROBE,
                PayloadRiskClass.HEADER_PROBE,
            )

    def test_no_destructive_or_exfiltration_in_builtins(self):
        blocked = {PayloadRiskClass.EXFILTRATION, PayloadRiskClass.DESTRUCTIVE}
        for p in BUILTIN_PAYLOADS:
            assert p.risk_class not in blocked

    def test_unique_ids(self):
        ids = [p.id for p in BUILTIN_PAYLOADS]
        assert len(ids) == len(set(ids))

    def test_all_have_descriptions(self):
        for p in BUILTIN_PAYLOADS:
            assert p.description and len(p.description) > 5


class TestPayloadDispatch:

    @pytest.fixture
    def dispatch(self):
        return PayloadDispatch()

    def test_builtins_loaded_at_init(self, dispatch):
        assert len(dispatch) == len(BUILTIN_PAYLOADS)

    def test_dispatch_safe_marker_ok(self, dispatch):
        safe = [p for p in BUILTIN_PAYLOADS if p.risk_class == PayloadRiskClass.SAFE_MARKER][0]
        result = dispatch.dispatch(safe.id)
        assert result.id == safe.id

    def test_dispatch_reflection_probe_ok(self, dispatch):
        probe = [p for p in BUILTIN_PAYLOADS if p.risk_class == PayloadRiskClass.REFLECTION_PROBE][0]
        result = dispatch.dispatch(probe.id)
        assert result.risk_class == PayloadRiskClass.REFLECTION_PROBE

    def test_dispatch_unknown_id_raises_keyerror(self, dispatch):
        with pytest.raises(KeyError):
            dispatch.dispatch("nonexistent_payload_id")

    def test_register_state_mutate_allowed(self, dispatch):
        p = Payload(id="my_mutate", risk_class=PayloadRiskClass.STATE_MUTATE,
                    value="DELETE /", description="test")
        dispatch.register(p)
        assert dispatch.get("my_mutate") is p

    def test_dispatch_state_mutate_blocked(self, dispatch):
        p = Payload(id="my_mutate2", risk_class=PayloadRiskClass.STATE_MUTATE,
                    value="DELETE /", description="test")
        dispatch.register(p)
        with pytest.raises(ProbeError):
            dispatch.dispatch("my_mutate2")

    def test_register_exfiltration_blocked(self, dispatch):
        p = Payload(id="exfil_test", risk_class=PayloadRiskClass.EXFILTRATION,
                    value="dns://evil", description="test")
        with pytest.raises(ProbeError, match="EXFILTRATION"):
            dispatch.register(p)

    def test_register_destructive_blocked(self, dispatch):
        p = Payload(id="drop_db", risk_class=PayloadRiskClass.DESTRUCTIVE,
                    value="DROP TABLE users", description="test")
        with pytest.raises(ProbeError, match="DESTRUCTIVE"):
            dispatch.register(p)

    def test_duplicate_id_raises(self, dispatch):
        first = BUILTIN_PAYLOADS[0]
        dup = Payload(id=first.id, risk_class=PayloadRiskClass.SAFE_MARKER,
                      value="x", description="d")
        with pytest.raises(ValueError):
            dispatch.register(dup)

    def test_list_by_class(self, dispatch):
        markers = dispatch.list_by_class(PayloadRiskClass.SAFE_MARKER)
        assert all(p.risk_class == PayloadRiskClass.SAFE_MARKER for p in markers)

    def test_all_payloads_returns_list(self, dispatch):
        all_p = dispatch.all_payloads()
        assert isinstance(all_p, list)
        assert len(all_p) == len(BUILTIN_PAYLOADS)

    def test_extra_payloads_at_init(self):
        extra = Payload(id="extra_safe", risk_class=PayloadRiskClass.SAFE_MARKER,
                        value="extra-value", description="extra")
        d = PayloadDispatch(extra_payloads=[extra])
        assert len(d) == len(BUILTIN_PAYLOADS) + 1
        assert d.get("extra_safe") is extra

    def test_error_message_names_class(self):
        dispatch = PayloadDispatch()
        p = Payload(id="my_destructive", risk_class=PayloadRiskClass.STATE_MUTATE,
                    value="v", description="d")
        dispatch.register(p)
        with pytest.raises(ProbeError) as exc_info:
            dispatch.dispatch("my_destructive")
        assert "state_mutate" in str(exc_info.value).lower()
