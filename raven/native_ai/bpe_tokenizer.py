"""RAVEN-owned byte-level BPE tokenizer — PURE PYTHON (stdlib only).

This is a real, RAVEN-owned tokenizer: no ``tokenizers``, no ``sentencepiece``, no
``tiktoken``, no external vocab, no downloads. It is the concrete byte-level
Byte-Pair-Encoding described in ``reconstruction/native_ai/ARCHITECTURE_DECISION.md`` §4.

Design (why it is total + multilingual for free):
  * **256-byte base alphabet** (ids 0..255). Every ``str`` encodes to UTF-8 bytes, so
    ANY input — Arabic, English, mixed, emoji, raw binary-ish technical text — encodes
    with ZERO out-of-vocabulary tokens. Arabic code points are multi-byte UTF-8 and are
    covered by the byte alphabet; merges learned over an AR/EN corpus build Arabic
    subwords with no script-specific logic.
  * **Protected structural tokens** (split-specials): ``<pad> <bos> <eos> <|system|>
    <|user|> <|raven|> <|endturn|>`` — matched atomically wherever they literally appear
    (chat templating) and never split.
  * **Protected technical atoms** (reserved ids): HTTP methods, common status codes,
    header names, URL schemes, JSON/code punctuation, shell/path pieces and
    ``CVE-``/``CWE-`` prefixes. Each owns a dedicated vocab id and is emitted atomically
    whenever a pre-token piece equals it, so it is never split. Word-shaped atoms (e.g.
    ``GET``) only match at word boundaries — ``TARGET`` is NOT atomized — while
    punctuation/compound atoms (e.g. ``content-type``) are isolated by the
    pre-tokenizer.
  * **Corpus-driven merges**: standard BPE merge-learning over byte sequences fills the
    remaining vocab from the training corpus.

Guarantees: deterministic + seed-free (training is a fixed function of the corpus),
round-trip lossless on bytes (``decode(encode(t)) == t`` for valid UTF-8 ``t``), and a
stable ``version`` + content ``hash`` for provenance. Serialized as plain JSON.

Not imported by any live runtime path; this module adds a capability, it does not wire
anything in. ``raven.native_ai.NATIVE_GENERATIVE_MODEL`` stays ``None``.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from typing import Dict, List, Optional, Tuple

VERSION = "raven-bbpe/1"

# Structural chat tokens — matched atomically by encode(), never split, never merged.
STRUCTURAL_TOKENS: Tuple[str, ...] = (
    "<pad>", "<bos>", "<eos>",
    "<|system|>", "<|user|>", "<|raven|>", "<|endturn|>",
)

# Curated technical atoms. Each owns a dedicated vocab id and is emitted atomically
# when a pre-token piece equals it. Space-free forms are used on purpose: a token with
# an internal space could never form (the pre-tokenizer splits on whitespace).
TECHNICAL_SEED_TOKENS: Tuple[str, ...] = (
    # HTTP methods
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
    # Common status codes
    "200", "201", "204", "301", "302", "304", "400", "401", "403",
    "404", "405", "409", "422", "429", "500", "502", "503",
    # Common header names (lower-case canonical)
    "content-type", "content-length", "authorization", "www-authenticate",
    "etag", "retry-after", "set-cookie", "location", "host", "user-agent",
    # URL / scheme pieces
    "http://", "https://", "://",
    # JSON / code punctuation runs (space-free)
    '{"', '":"', '"}', "[]", "::", "={", "})",
    # Shell / path pieces
    "/", "./", "../", "--", "$(", ")",
    # Vulnerability-ID prefixes
    "CVE-", "CWE-",
)

_BASE_PRETOK = re.compile(r"\w+|\s+|[^\w\s]+", re.UNICODE)


def _pretok_regex(tech_tokens: Tuple[str, ...]) -> "re.Pattern[str]":
    """Build the pre-tokenization regex.

    Multi-character atoms that contain punctuation (e.g. ``content-type``, ``http://``,
    ``::``) are listed FIRST, longest-first, so they are isolated as a single piece.
    Word-shaped atoms (``GET``, ``200``, ``authorization``) are deliberately NOT listed
    — they are recognized only when a whole ``\\w+`` piece equals them, which avoids
    atomizing substrings inside larger words. ``\\w+`` is Unicode-aware, so Arabic runs
    stay grouped.
    """
    isolate = [t for t in tech_tokens if len(t) > 1 and not t.isalnum()]
    isolate.sort(key=len, reverse=True)
    alt = "".join(re.escape(c) + "|" for c in isolate)
    return re.compile(alt + r"\w+|\s+|[^\w\s]+", re.UNICODE)


class ByteLevelBPETokenizer:
    """RAVEN-owned pure-Python byte-level BPE tokenizer."""

    def __init__(self) -> None:
        self._token_bytes: Dict[int, bytes] = {i: bytes([i]) for i in range(256)}
        self._special_to_id: Dict[str, int] = {}     # structural token -> id
        self._tech_to_id: Dict[str, int] = {}         # technical atom -> id
        self._merges: Dict[Tuple[int, int], int] = {}
        self._ranks: Dict[Tuple[int, int], int] = {}
        self._next_id = 256
        self._special_re: Optional["re.Pattern[str]"] = None
        self._pretok_re: "re.Pattern[str]" = _pretok_regex(TECHNICAL_SEED_TOKENS)
        self._hash = ""
        self._install_structural_tokens()
        self._install_technical_atoms()

    # ── construction helpers ──────────────────────────────────────────────────

    def _install_structural_tokens(self) -> None:
        for tok in STRUCTURAL_TOKENS:
            tid = self._next_id
            self._next_id += 1
            self._special_to_id[tok] = tid
            self._token_bytes[tid] = tok.encode("utf-8")
        ordered = sorted(self._special_to_id, key=len, reverse=True)
        self._special_re = re.compile("|".join(re.escape(t) for t in ordered))

    def _install_technical_atoms(self) -> None:
        for tok in TECHNICAL_SEED_TOKENS:
            if tok in self._tech_to_id:
                continue
            raw = tok.encode("utf-8")
            if len(raw) == 1:
                # single byte: protected by being a base token
                self._tech_to_id[tok] = raw[0]
                continue
            tid = self._next_id
            self._next_id += 1
            self._tech_to_id[tok] = tid
            self._token_bytes[tid] = raw

    def _new_merge(self, a: int, b: int) -> int:
        existing = self._merges.get((a, b))
        if existing is not None:
            return existing
        new_id = self._next_id
        self._next_id += 1
        self._token_bytes[new_id] = self._token_bytes[a] + self._token_bytes[b]
        self._merges[(a, b)] = new_id
        self._ranks[(a, b)] = len(self._ranks)
        return new_id

    # ── pre-tokenization / special splitting ─────────────────────────────────

    def _split_on_specials(self, text: str) -> List[Tuple[bool, str]]:
        if self._special_re is None:
            return [(False, text)]
        out: List[Tuple[bool, str]] = []
        pos = 0
        for m in self._special_re.finditer(text):
            if m.start() > pos:
                out.append((False, text[pos:m.start()]))
            out.append((True, m.group(0)))
            pos = m.end()
        if pos < len(text):
            out.append((False, text[pos:]))
        return out

    def _bpe_bytes(self, ids: List[int]) -> List[int]:
        if len(ids) < 2:
            return ids
        ids = list(ids)
        while True:
            best_rank = None
            best_pos = -1
            for i in range(len(ids) - 1):
                r = self._ranks.get((ids[i], ids[i + 1]))
                if r is not None and (best_rank is None or r < best_rank):
                    best_rank = r
                    best_pos = i
            if best_pos < 0:
                break
            a, b = ids[best_pos], ids[best_pos + 1]
            ids[best_pos:best_pos + 2] = [self._merges[(a, b)]]
        return ids

    def _encode_piece(self, piece: str) -> List[int]:
        tid = self._tech_to_id.get(piece)
        if tid is not None:
            return [tid]
        return self._bpe_bytes(list(piece.encode("utf-8")))

    # ── public API ───────────────────────────────────────────────────────────

    def train(self, corpus: List[str], vocab_size: int = 4096) -> "ByteLevelBPETokenizer":
        """Learn merges from ``corpus`` up to ``vocab_size`` total tokens.

        Fully deterministic: a pure function of ``corpus`` and ``vocab_size`` (ties
        broken lexicographically). No RNG, no threads, no I/O during training.
        """
        reserved = 256 + len(self._special_to_id) + sum(
            1 for t in TECHNICAL_SEED_TOKENS if len(t.encode("utf-8")) > 1
        )
        if vocab_size < reserved:
            raise ValueError(
                f"vocab_size={vocab_size} too small; need >= {reserved} "
                "for base bytes + protected tokens"
            )
        self._merges.clear()
        self._ranks.clear()
        self._next_id = max(self._token_bytes) + 1

        # frequency table over pre-token pieces; protected atoms contribute no pairs
        freqs: Counter = Counter()
        for doc in corpus:
            for is_special, chunk in self._split_on_specials(doc):
                if is_special or not chunk:
                    continue
                for piece in self._pretok_re.findall(chunk):
                    if piece in self._tech_to_id:
                        continue  # atom is atomic — never merged into/out of
                    b = tuple(piece.encode("utf-8"))
                    if b:
                        freqs[b] += 1

        words: List[List[int]] = [list(k) for k in freqs]
        counts: List[int] = [freqs[k] for k in freqs]

        while self._next_id < vocab_size:
            pair_freq: Counter = Counter()
            for w, c in zip(words, counts):
                for i in range(len(w) - 1):
                    pair_freq[(w[i], w[i + 1])] += c
            if not pair_freq:
                break
            max_f = max(pair_freq.values())
            best_pair = min(
                (p for p, f in pair_freq.items() if f == max_f),
                key=lambda p: (self._token_bytes[p[0]], self._token_bytes[p[1]]),
            )
            new_id = self._new_merge(*best_pair)
            a, b = best_pair
            for w in words:
                i = 0
                while i < len(w) - 1:
                    if w[i] == a and w[i + 1] == b:
                        w[i:i + 2] = [new_id]
                    else:
                        i += 1

        self._recompute_hash()
        return self

    def encode(self, text: str) -> List[int]:
        out: List[int] = []
        for is_special, chunk in self._split_on_specials(text):
            if is_special:
                out.append(self._special_to_id[chunk])
                continue
            for piece in self._pretok_re.findall(chunk):
                out.extend(self._encode_piece(piece))
        return out

    def decode(self, tokens: List[int]) -> str:
        raw = b"".join(self._token_bytes[int(t)] for t in tokens)
        return raw.decode("utf-8", errors="replace")

    @property
    def vocab_size(self) -> int:
        return len(self._token_bytes)

    @property
    def version(self) -> str:
        return VERSION

    @property
    def hash(self) -> str:
        if not self._hash:
            self._recompute_hash()
        return self._hash

    def special_token_id(self, token: str) -> int:
        return self._special_to_id[token]

    def technical_token_id(self, token: str) -> Optional[int]:
        return self._tech_to_id.get(token)

    def is_protected_single_token(self, token: str) -> bool:
        return len(self.encode(token)) == 1

    # ── persistence ────────────────────────────────────────────────────────────

    def _canonical(self) -> dict:
        return {
            "version": VERSION,
            "specials": {t: i for t, i in sorted(self._special_to_id.items())},
            "technical": {t: i for t, i in sorted(self._tech_to_id.items())},
            "merges": [
                [a, b, nid]
                for (a, b), nid in sorted(self._merges.items(), key=lambda kv: self._ranks[kv[0]])
            ],
            "token_bytes": {
                str(i): self._token_bytes[i].decode("latin-1")
                for i in sorted(self._token_bytes)
            },
        }

    def _recompute_hash(self) -> None:
        blob = json.dumps(self._canonical(), sort_keys=True, ensure_ascii=True).encode("utf-8")
        self._hash = hashlib.sha256(blob).hexdigest()

    def save(self, path: str) -> str:
        payload = dict(self._canonical())
        payload["hash"] = self.hash
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=True, indent=2)
        return path

    @classmethod
    def load(cls, path: str) -> "ByteLevelBPETokenizer":
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: dict) -> "ByteLevelBPETokenizer":
        tok = cls.__new__(cls)
        tok._token_bytes = {
            int(i): s.encode("latin-1") for i, s in payload["token_bytes"].items()
        }
        tok._special_to_id = {t: int(i) for t, i in payload["specials"].items()}
        tok._tech_to_id = {t: int(i) for t, i in payload.get("technical", {}).items()}
        tok._merges = {}
        tok._ranks = {}
        for rank, (a, b, nid) in enumerate(payload["merges"]):
            tok._merges[(int(a), int(b))] = int(nid)
            tok._ranks[(int(a), int(b))] = rank
        tok._next_id = (max(tok._token_bytes) + 1) if tok._token_bytes else 256
        ordered = sorted(tok._special_to_id, key=len, reverse=True)
        tok._special_re = re.compile("|".join(re.escape(t) for t in ordered)) if ordered else None
        tok._pretok_re = _pretok_regex(TECHNICAL_SEED_TOKENS)
        tok._hash = payload.get("hash", "")
        if not tok._hash:
            tok._recompute_hash()
        return tok
