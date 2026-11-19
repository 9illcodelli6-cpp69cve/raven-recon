"""Native chat must never show the chat template's structural tokens.

Regression: the bootstrap model's reply reached the UI as
``NORMAL_SUCCESS<|endturn|><eos>`` because the engine decodes special tokens
literally and the provider passed the raw text through.
"""
import pytest

pytest.importorskip("torch")

from raven.native_ai.generative import chat_provider as cp  # noqa: E402


@pytest.mark.parametrize("raw, expected", [
    ("NORMAL_SUCCESS<|endturn|><eos>", "NORMAL_SUCCESS"),
    ("NOT_FOUND<eos>", "NOT_FOUND"),
    ("answer<|user|>next question<|raven|>more", "answer"),
    ("<bos>  hello <pad>", "hello"),
    ("plain text", "plain text"),
    ("<|endturn|>", ""),
    ("", ""),
])
def test_clean_reply(raw, expected):
    assert cp._clean_reply(raw) == expected


class _FakeEngine:
    maturity = "EXPERIMENTAL_BOOTSTRAP"

    def __init__(self, text, pieces=()):
        self._text, self._pieces = text, list(pieces)

    def generate(self, prompt, cfg):
        class R:
            pass
        r = R()
        r.text, r.tokens = self._text, [1, 2, 3]
        return r

    def stream(self, prompt, cfg):
        yield from self._pieces


def test_complete_strips_markers_but_keeps_maturity_metadata():
    p = cp.NativeChatProvider(engine=_FakeEngine("NORMAL_SUCCESS<|endturn|><eos>"))
    res = p.complete([{"role": "user", "content": "hi"}])
    assert res.content == "NORMAL_SUCCESS"
    assert res.usage["maturity"] == "EXPERIMENTAL_BOOTSTRAP"
    assert res.is_advisory


def test_stream_stops_at_end_of_turn():
    p = cp.NativeChatProvider(engine=_FakeEngine("", ["NOR", "MAL", "<|endturn|>", "junk"]))
    assert "".join(p.stream([{"role": "user", "content": "hi"}])) == "NORMAL"
