"""Local cybersecurity knowledge base — SQLite FTS5 (BM25) over the trusted corpus.

Used two ways: (1) the research agent's ``search`` tool answers from it first (fast,
offline, cited); (2) the training-set builder reads the same documents.
"""
from __future__ import annotations

import re
import sqlite3
import threading
from pathlib import Path
from typing import List, Optional

from . import corpus, paths

_CHUNK = 1400
_NOISE_HEADINGS = {"summary", "table of contents", "contents", "references", "labs",
                   "related", "related attacks", "see also"}
_TOKEN = re.compile(r"[A-Za-z0-9_\-\.]{2,}")
_STOP = {"the", "and", "for", "how", "what", "with", "this", "that", "from", "are", "can",
         "you", "does", "do", "is", "in", "of", "to", "on", "an", "or", "me", "my", "it", "be"}


def _chunks(text: str, size: int = _CHUNK) -> List[str]:
    text = text.strip()
    if len(text) <= size:
        return [text] if text else []
    out, buf = [], ""
    for para in text.split("\n\n"):
        if len(buf) + len(para) + 2 > size and buf:
            out.append(buf.strip())
            buf = ""
        while len(para) > size:
            out.append(para[:size])
            para = para[size:]
        buf += para + "\n\n"
    if buf.strip():
        out.append(buf.strip())
    return out


def build(raw: Optional[Path] = None, db_path: Optional[Path] = None) -> dict:
    """(Re)build the FTS index from every document under ``raw``. Returns counts."""
    raw = Path(raw or paths.corpus_raw_dir())
    db_path = Path(db_path or paths.kb_path())
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = db_path.with_suffix(".tmp")
    if tmp.exists():
        tmp.unlink()
    con = sqlite3.connect(tmp)
    con.execute("CREATE VIRTUAL TABLE chunks USING fts5(doc_id UNINDEXED, source UNINDEXED, "
                "title, heading, url UNINDEXED, body, tokenize='porter unicode61')")
    con.execute("CREATE TABLE docs(doc_id TEXT PRIMARY KEY, source TEXT, title TEXT, url TEXT, body TEXT)")
    counts: dict = {}
    for doc in corpus.iter_all(raw):
        counts[doc.source] = counts.get(doc.source, 0) + 1
        con.execute("INSERT OR REPLACE INTO docs VALUES(?,?,?,?,?)",
                    (doc.doc_id, doc.source, doc.title, doc.url, doc.text()))
        for heading, text in doc.sections:
            for piece in _chunks(text):
                con.execute("INSERT INTO chunks VALUES(?,?,?,?,?,?)",
                            (doc.doc_id, doc.source, doc.title, heading, doc.url, piece))
    con.commit()
    counts["chunks"] = con.execute("SELECT count(*) FROM chunks").fetchone()[0]
    con.close()
    tmp.replace(db_path)
    return counts


# Researchers ask with acronyms; the trusted documents are titled with the full names
# ("IDOR" vs "Insecure Direct Object References"). Each acronym adds its phrase(s).
_EXPAND = {
    "idor": ("insecure direct object", "object level authorization"),
    "bola": ("object level authorization", "insecure direct object"),
    "bfla": ("function level authorization",),
    "ssrf": ("server side request forgery",),
    "xss": ("cross site scripting",),
    "sqli": ("sql injection",),
    "ssti": ("template injection",),
    "xxe": ("xml external entity",),
    "csrf": ("cross site request forgery",),
    "xsrf": ("cross site request forgery",),
    "rce": ("remote code execution", "command injection"),
    "lfi": ("local file inclusion", "path traversal"),
    "rfi": ("remote file inclusion",),
    "jwt": ("json web token",),
    "cors": ("cross origin resource sharing",),
    "crlf": ("crlf injection",),
    "nosqli": ("nosql injection",),
    "deserialization": ("insecure deserialization",),
}


def fts_query(text: str) -> str:
    """Free text → a safe FTS5 query (quoted terms OR-ed; BM25 does the ranking)."""
    terms, phrases = [], []
    for t in _TOKEN.findall(str(text).lower()):
        t = t.strip(".-")
        if len(t) < 2 or t in _STOP or t in terms:
            continue
        terms.append(t)
        for part in {t, *t.split("-")}:          # "jwt-protected" → jwt
            for ph in _EXPAND.get(part, ()):
                if ph not in phrases:
                    phrases.append(ph)
    items = phrases[:4] + terms[:16]
    return " OR ".join('"' + t.replace('"', "") + '"' for t in items)


class KnowledgeBase:
    def __init__(self, db_path: Optional[Path] = None):
        self.path = Path(db_path or paths.kb_path())
        self._lock = threading.Lock()
        self._con = None

    @property
    def available(self) -> bool:
        return self.path.is_file()

    def _db(self):
        if self._con is None:
            # Path.as_uri() percent-encodes "?", "#", "%" … in the path (a raw f-string
            # URI broke on such paths and could open/create the wrong file).
            self._con = sqlite3.connect(Path(self.path).absolute().as_uri() + "?mode=ro", uri=True,
                                        check_same_thread=False)
        return self._con

    def search(self, query: str, k: int = 5, sources: Optional[List[str]] = None) -> List[dict]:
        if not self.available:
            return []
        q = fts_query(query)
        if not q:
            return []
        sql = ("SELECT doc_id, source, title, heading, url, body, "
               "bm25(chunks, 0, 0, 6.0, 3.0, 0, 1.0) AS score FROM chunks WHERE chunks MATCH ?")
        args: list = [q]
        if sources:
            sql += " AND source IN (%s)" % ",".join("?" * len(sources))
            args += list(sources)
        sql += " ORDER BY score LIMIT ?"
        args.append(int(k) * 3)
        with self._lock:
            rows = self._db().execute(sql, args).fetchall()
        seen, out = set(), []
        for doc_id, source, title, heading, url, body, score in rows:
            key = (doc_id, heading)
            # Navigation-only sections (tables of contents, link lists) match many query
            # words but carry no answer — skip them.
            if key in seen or (heading or "").strip().lower() in _NOISE_HEADINGS:
                continue
            seen.add(key)
            out.append({"doc_id": doc_id, "source": source, "title": title, "heading": heading,
                        "url": url, "text": body, "score": round(-score, 3)})
            if len(out) >= k:
                break
        return out

    def has_url(self, url: str) -> bool:
        """True when ``url`` is a page of the local trusted corpus."""
        if not self.available or not url:
            return False
        u = url.split("#", 1)[0]
        with self._lock:
            row = self._db().execute("SELECT 1 FROM docs WHERE url=? OR url=? LIMIT 1",
                                     (u, u.rstrip("/"))).fetchone()
        return row is not None

    def get(self, doc_id: str) -> Optional[dict]:
        if not self.available:
            return None
        with self._lock:
            row = self._db().execute("SELECT doc_id, source, title, url, body FROM docs WHERE doc_id=?",
                                     (doc_id,)).fetchone()
        return dict(zip(("doc_id", "source", "title", "url", "text"), row)) if row else None

    def stats(self) -> dict:
        if not self.available:
            return {"available": False}
        with self._lock:
            rows = self._db().execute("SELECT source, count(*) FROM docs GROUP BY source").fetchall()
            chunks = self._db().execute("SELECT count(*) FROM chunks").fetchone()[0]
        return {"available": True, "documents": dict(rows), "chunks": chunks}
