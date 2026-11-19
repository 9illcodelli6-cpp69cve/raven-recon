"""RAVEN V7 Conversation Context.

Multi-turn conversation memory with workspace isolation (§116-117, §307-309).
Conversation memory ≠ model context — see Part 03 for full memory architecture.
This Bootstrap module provides the persistence layer; Context Builder (Part 03) handles
assembly and retrieval.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class MessageRole(str, Enum):
    RESEARCHER   = "researcher"
    RAVEN        = "raven"
    SYSTEM_EVENT = "system_event"
    TOOL_RESULT  = "tool_result"


@dataclass
class Message:
    """A single conversation message (§308)."""
    message_id:     str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    conversation_id: str = ""
    role:           MessageRole = MessageRole.RESEARCHER
    content:        str = ""
    language:       Optional[str] = None   # "ar" / "en" / "mixed" / None
    created_at:     int = field(default_factory=lambda: int(time.time() * 1000))
    task_id:        Optional[str] = None
    model_id:       Optional[str] = None
    references:     List[str] = field(default_factory=list)  # [OBS-nnn], [EXEC-nnn], etc.
    metadata:       Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "conversation_id": self.conversation_id,
            "role": self.role.value,
            "content": self.content,
            "language": self.language,
            "created_at": self.created_at,
            "task_id": self.task_id,
            "model_id": self.model_id,
            "references": self.references,
        }


@dataclass
class Conversation:
    """A conversation tied to a workspace (§307)."""
    conversation_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    workspace_id:    str = ""
    title:           str = ""
    created_at:      int = field(default_factory=lambda: int(time.time() * 1000))
    updated_at:      int = field(default_factory=lambda: int(time.time() * 1000))
    active_task_id:  Optional[str] = None
    selected_model:  Optional[str] = None
    language_state:  Optional[str] = None   # dominant language of this session
    metadata:        Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "conversation_id": self.conversation_id,
            "workspace_id": self.workspace_id,
            "title": self.title,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "active_task_id": self.active_task_id,
            "selected_model": self.selected_model,
            "language_state": self.language_state,
        }


class ConversationContext:
    """Manages in-memory + persisted conversation state.

    Bounded: max_turns limits active history. Older messages are persisted
    but not kept in RAM. This prevents unbounded memory growth (§420).
    """

    def __init__(self, db: sqlite3.Connection, max_turns: int = 100):
        self._db = db
        self._max_turns = max_turns
        self._lock = threading.RLock()
        self._migrate()
        self._conversations: Dict[str, Conversation] = {}
        self._active_messages: Dict[str, List[Message]] = {}  # conv_id → recent messages

    def _migrate(self) -> None:
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS v7_conversations (
            conversation_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            title TEXT,
            created_at INTEGER,
            updated_at INTEGER,
            active_task_id TEXT,
            selected_model TEXT,
            language_state TEXT,
            metadata_json TEXT
        );
        CREATE INDEX IF NOT EXISTS v7_conv_workspace ON v7_conversations(workspace_id);

        CREATE TABLE IF NOT EXISTS v7_messages (
            message_id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            language TEXT,
            created_at INTEGER,
            task_id TEXT,
            model_id TEXT,
            references_json TEXT,
            metadata_json TEXT,
            FOREIGN KEY (conversation_id) REFERENCES v7_conversations(conversation_id)
        );
        CREATE INDEX IF NOT EXISTS v7_msg_conv ON v7_messages(conversation_id, created_at);
        """)
        self._db.commit()

    def create_conversation(self, workspace_id: str, title: str = "",
                            model_id: str = None) -> Conversation:
        conv = Conversation(
            workspace_id=workspace_id,
            title=title,
            selected_model=model_id,
        )
        with self._lock:
            self._conversations[conv.conversation_id] = conv
            self._active_messages[conv.conversation_id] = []
        self._persist_conversation(conv)
        return conv

    def get_conversation(self, conversation_id: str) -> Optional[Conversation]:
        with self._lock:
            if conversation_id in self._conversations:
                return self._conversations[conversation_id]
        # Load from DB
        row = self._db.execute(
            "SELECT * FROM v7_conversations WHERE conversation_id=?", (conversation_id,)
        ).fetchone()
        if row is None:
            return None
        conv = self._row_to_conversation(dict(row))
        with self._lock:
            self._conversations[conversation_id] = conv
        return conv

    def add_message(self, conversation_id: str, role: MessageRole,
                    content: str, language: str = None, task_id: str = None,
                    model_id: str = None, references: List[str] = None) -> Message:
        msg = Message(
            conversation_id=conversation_id,
            role=role,
            content=content,
            language=language,
            task_id=task_id,
            model_id=model_id,
            references=references or [],
        )
        with self._lock:
            msgs = self._active_messages.setdefault(conversation_id, [])
            msgs.append(msg)
            # Bound active history in RAM
            if len(msgs) > self._max_turns:
                self._active_messages[conversation_id] = msgs[-self._max_turns:]
            # Update conversation timestamp
            if conversation_id in self._conversations:
                self._conversations[conversation_id].updated_at = msg.created_at
        self._persist_message(msg)
        return msg

    def get_recent(self, conversation_id: str, n: int = 20) -> List[Message]:
        with self._lock:
            msgs = self._active_messages.get(conversation_id)
            if msgs is not None:
                return list(msgs[-n:])
        # Not in RAM — load from DB
        rows = self._db.execute(
            "SELECT * FROM v7_messages WHERE conversation_id=? ORDER BY created_at DESC LIMIT ?",
            (conversation_id, n)
        ).fetchall()
        return list(reversed([self._row_to_message(dict(r)) for r in rows]))

    def list_conversations(self, workspace_id: str) -> List[Conversation]:
        rows = self._db.execute(
            "SELECT * FROM v7_conversations WHERE workspace_id=? ORDER BY updated_at DESC",
            (workspace_id,)
        ).fetchall()
        return [self._row_to_conversation(dict(r)) for r in rows]

    def clear(self, conversation_id: str) -> None:
        """Remove active messages from RAM (they stay persisted)."""
        with self._lock:
            self._active_messages.pop(conversation_id, None)

    def _persist_conversation(self, conv: Conversation) -> None:
        with self._lock:
            self._db.execute("""
            INSERT OR REPLACE INTO v7_conversations
                (conversation_id, workspace_id, title, created_at, updated_at,
                 active_task_id, selected_model, language_state, metadata_json)
            VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                conv.conversation_id, conv.workspace_id, conv.title,
                conv.created_at, conv.updated_at, conv.active_task_id,
                conv.selected_model, conv.language_state, json.dumps(conv.metadata),
            ))
            self._db.commit()

    def _persist_message(self, msg: Message) -> None:
        with self._lock:
            self._db.execute("""
            INSERT OR REPLACE INTO v7_messages
                (message_id, conversation_id, role, content, language, created_at,
                 task_id, model_id, references_json, metadata_json)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                msg.message_id, msg.conversation_id, msg.role.value, msg.content,
                msg.language, msg.created_at, msg.task_id, msg.model_id,
                json.dumps(msg.references), json.dumps(msg.metadata),
            ))
            self._db.commit()

    def _row_to_conversation(self, row: dict) -> Conversation:
        return Conversation(
            conversation_id=row["conversation_id"],
            workspace_id=row["workspace_id"],
            title=row.get("title", ""),
            created_at=row.get("created_at", 0),
            updated_at=row.get("updated_at", 0),
            active_task_id=row.get("active_task_id"),
            selected_model=row.get("selected_model"),
            language_state=row.get("language_state"),
            metadata=json.loads(row.get("metadata_json") or "{}"),
        )

    def _row_to_message(self, row: dict) -> Message:
        return Message(
            message_id=row["message_id"],
            conversation_id=row["conversation_id"],
            role=MessageRole(row["role"]),
            content=row["content"],
            language=row.get("language"),
            created_at=row.get("created_at", 0),
            task_id=row.get("task_id"),
            model_id=row.get("model_id"),
            references=json.loads(row.get("references_json") or "[]"),
            metadata=json.loads(row.get("metadata_json") or "{}"),
        )
