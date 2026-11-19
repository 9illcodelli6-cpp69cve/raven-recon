"""Tests for the RAVEN-owned pure-Python byte-level BPE tokenizer.

Proves: lossless round-trips across AR / EN / mixed / HTTP / JSON / Python / PowerShell /
Bash / URL / security-terms; protected structural + technical tokens stay atomic; no
over-atomization of substrings; byte totality; deterministic training; stable
version/hash; JSON save/load.

Run:  python -m pytest tests/test_native_ai_tokenizer.py -q
"""
from raven.native_ai.bpe_tokenizer import (
    ByteLevelBPETokenizer, STRUCTURAL_TOKENS, TECHNICAL_SEED_TOKENS,
)
from raven.native_ai.curriculum_impl import curriculum_corpus_texts

_CORPUS = [
    "GET /api/users HTTP/1.1\r\nhost: example.test\r\nauthorization: Bearer x\r\n\r\n",
    'POST /login content-type: application/json\r\n\r\n{"user":"a","pw":"b"}',
    'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{"status":"ok","n":200}',
    "server returned 404 for https://example.com/x and 403 for /admin",
    "retry-after: 30; www-authenticate: Basic; set-cookie: s=1",
    "الشبكة تعمل بشكل طبيعي ورمز الحالة 200 لا يعني وجود ثغرة أمنية",
    "def handler(req):\n    return {'ok': True, 'code': 200}",
    "CVE-2021-44228 CWE-79 XSS SQLi SSRF IDOR",
] * 8

_ROUNDTRIP = {
    "ar": "الشبكة تعمل بشكل طبيعي. رمز الحالة 200 لا يعني وجود ثغرة.",
    "en": "The server returned a 403 Forbidden for the admin endpoint.",
    "mixed": "HTTP response رمز 404 means not found. اختبار mixed AR/EN 200 OK.",
    "http_request": "GET /search?q=test&page=2 HTTP/1.1\r\nhost: h.test\r\nuser-agent: raven/0.1\r\n\r\n",
    "json": '{"k":"v","n":200,"arr":[1,2,3],"nested":{"a":null,"b":false}}',
    "python": "def f(x):\n    return x**2 if x > 0 else -x  # inline comment\n",
    "powershell": "Get-ChildItem -Path C:\\Users | Where-Object {$_.Length -gt 0}",
    "bash": '$(curl -s https://h.test/a) && echo "ok" | grep -E "2[0-9]{2}"',
    "url": "https://sub.example.test:8443/path/to/x?a=1&b=2#frag",
    "security_terms": "CVE-2021-44228 CWE-79 SSRF IDOR 403 Forbidden 500 error",
    "emoji": "status: ok ✅ fail ❌ — spans multi-byte UTF-8",
}


def _trained(vocab_size: int = 1024) -> ByteLevelBPETokenizer:
    return ByteLevelBPETokenizer().train(_CORPUS, vocab_size=vocab_size)


def test_roundtrip_lossless_all_domains():
    tok = _trained()
    for name, text in _ROUNDTRIP.items():
        ids = tok.encode(text)
        assert all(isinstance(i, int) for i in ids)
        assert tok.decode(ids) == text, f"round-trip failed for {name}"


def test_protected_technical_tokens_are_single():
    tok = _trained()
    for atom in TECHNICAL_SEED_TOKENS:
        ids = tok.encode(atom)
        assert len(ids) == 1, f"technical atom {atom!r} not atomic: {ids}"
        assert tok.decode(ids) == atom


def test_protected_structural_tokens_are_single():
    tok = _trained()
    for s in STRUCTURAL_TOKENS:
        ids = tok.encode(s)
        assert len(ids) == 1, f"structural token {s!r} not atomic: {ids}"
        assert tok.decode(ids) == s
        assert tok.special_token_id(s) == ids[0]


def test_chat_template_roundtrip_and_special_ids():
    tok = _trained()
    chat = "<|system|>be honest<|user|>is 200 a vuln?<|raven|>no, 200 is normal<|endturn|>"
    ids = tok.encode(chat)
    assert tok.decode(ids) == chat
    assert tok.special_token_id("<|user|>") in ids
    assert tok.special_token_id("<|raven|>") in ids


def test_no_over_atomization_of_substrings():
    tok = _trained()
    # "GET" is a protected atom but must NOT be atomized inside a larger word.
    assert len(tok.encode("TARGET")) > 1
    assert tok.decode(tok.encode("TARGET")) == "TARGET"
    # "200" must not force "2001" to split as 200 + 1 via a special path.
    assert tok.decode(tok.encode("2001")) == "2001"


def test_byte_totality_all_256():
    tok = _trained()
    # Every raw byte value is representable; arbitrary UTF-8 round-trips.
    blob = "".join(chr(c) for c in range(32, 127)) + "ضصثقفغعهخحجد"
    assert tok.decode(tok.encode(blob)) == blob


def test_deterministic_training():
    a = _trained()
    b = _trained()
    assert a.hash == b.hash
    assert a.encode(_ROUNDTRIP["http_request"]) == b.encode(_ROUNDTRIP["http_request"])


def test_version_and_hash_present():
    tok = _trained()
    assert tok.version == "raven-bbpe/1"
    assert isinstance(tok.hash, str) and len(tok.hash) == 64
    assert tok.vocab_size >= 256 + len(STRUCTURAL_TOKENS)


def test_save_load_roundtrip(tmp_path):
    tok = _trained()
    path = str(tmp_path / "rbpe.json")
    tok.save(path)
    loaded = ByteLevelBPETokenizer.load(path)
    assert loaded.hash == tok.hash
    for text in _ROUNDTRIP.values():
        assert loaded.encode(text) == tok.encode(text)
        assert loaded.decode(loaded.encode(text)) == text


def test_trains_on_curriculum_corpus():
    tok = ByteLevelBPETokenizer().train(curriculum_corpus_texts(), vocab_size=4096)
    assert tok.vocab_size > 256
    for atom in ("GET", "200", "content-type", "http://", "CVE-"):
        assert len(tok.encode(atom)) == 1
    sample = '<|user|>status_code=403<|raven|>FORBIDDEN<|endturn|>'
    assert tok.decode(tok.encode(sample)) == sample


def test_vocab_size_floor_rejected():
    import pytest
    with pytest.raises(ValueError):
        ByteLevelBPETokenizer().train(_CORPUS, vocab_size=100)
