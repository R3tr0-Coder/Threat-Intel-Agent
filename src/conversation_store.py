import json
import sqlite3
import uuid
from datetime import datetime
from typing import Optional

from src.models import ConversationTurn, ToolResult, IntentClassification, IntentType, TraceStep


def migrate_metrics_table(db_path: str = "conversations.db"):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("ALTER TABLE metrics ADD COLUMN rate_limiter_state TEXT NOT NULL DEFAULT '{}'")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    finally:
        conn.close()


class ConversationStore:
    def __init__(self, db_path: str = "conversations.db"):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id TEXT PRIMARY KEY,
                    title TEXT DEFAULT 'New Conversation',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    turn_data TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_messages_conv_id ON messages(conversation_id);
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    llm_usage TEXT NOT NULL DEFAULT '{}',
                    call_count TEXT NOT NULL DEFAULT '{}'
                );
            """)
            try:
                conn.execute("ALTER TABLE metrics ADD COLUMN rate_limiter_state TEXT NOT NULL DEFAULT '{}'")
            except sqlite3.OperationalError:
                pass
        finally:
            conn.close()

    def create_conversation(self, title: str = "New Conversation") -> str:
        conv_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        conn = self._get_conn()
        try:
            conn.execute(
                "INSERT INTO conversations (id, title, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (conv_id, title, now, now),
            )
            conn.commit()
        finally:
            conn.close()
        return conv_id

    def save_message(self, conversation_id: str, role: str, content: str, turn_data: Optional[dict] = None):
        now = datetime.utcnow().isoformat()
        conn = self._get_conn()
        try:
            conn.execute(
                "INSERT INTO messages (conversation_id, role, content, turn_data, timestamp) VALUES (?, ?, ?, ?, ?)",
                (conversation_id, role, content, json.dumps(turn_data) if turn_data else None, now),
            )
            conn.execute(
                "UPDATE conversations SET updated_at = ? WHERE id = ?",
                (now, conversation_id),
            )
            conn.commit()
        finally:
            conn.close()

    def save_turn(self, conversation_id: str, query: str, turn: ConversationTurn):
        self.save_message(conversation_id, "user", query)
        self.save_message(conversation_id, "assistant", turn.response, turn_data=turn.model_dump())

    def get_messages(self, conversation_id: str) -> list[dict]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT role, content, turn_data, timestamp FROM messages WHERE conversation_id = ? ORDER BY id ASC",
                (conversation_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def restore_turns(self, conversation_id: str) -> list[ConversationTurn]:
        turns = []
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT turn_data FROM messages WHERE conversation_id = ? AND role = 'assistant' AND turn_data IS NOT NULL ORDER BY id ASC",
                (conversation_id,),
            ).fetchall()
            for r in rows:
                data = json.loads(r["turn_data"])
                turns.append(ConversationTurn(**data))
        finally:
            conn.close()
        return turns

    def list_conversations(self) -> list[dict]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT id, title, created_at, updated_at FROM conversations ORDER BY updated_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_conversation(self, conversation_id: str) -> Optional[dict]:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT id, title, created_at, updated_at FROM conversations WHERE id = ?",
                (conversation_id,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def update_title(self, conversation_id: str, title: str):
        now = datetime.utcnow().isoformat()
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE conversations SET title = ?, updated_at = ? WHERE id = ?",
                (title, now, conversation_id),
            )
            conn.commit()
        finally:
            conn.close()

    def delete_conversation(self, conversation_id: str):
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM messages WHERE conversation_id = ?", (conversation_id,))
            conn.execute("DELETE FROM conversations WHERE id = ?", (conversation_id,))
            conn.commit()
        finally:
            conn.close()

    def search_conversations(self, query: str) -> list[dict]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT id, title, created_at, updated_at FROM conversations WHERE title LIKE ? ORDER BY updated_at DESC",
                (f"%{query}%",),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def sync_messages(self, conversation_id: str, messages: list[dict]):
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM messages WHERE conversation_id = ?", (conversation_id,))
            now = datetime.utcnow().isoformat()
            for msg in messages:
                role = msg["role"]
                content = msg["content"]
                turn_data = msg.get("turn_data")
                conn.execute(
                    "INSERT INTO messages (conversation_id, role, content, turn_data, timestamp) VALUES (?, ?, ?, ?, ?)",
                    (conversation_id, role, content,
                     json.dumps(turn_data) if turn_data else None, now),
                )
            conn.execute("UPDATE conversations SET updated_at = ? WHERE id = ?", (now, conversation_id))
            conn.commit()
        finally:
            conn.close()

    def get_metrics(self) -> dict:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT llm_usage, call_count FROM metrics WHERE id = 1").fetchone()
            if row:
                return {
                    "llm_usage": json.loads(row["llm_usage"]),
                    "call_count": json.loads(row["call_count"]),
                }
            return {"llm_usage": {}, "call_count": {}}
        finally:
            conn.close()

    def save_metrics(self, llm_usage: dict, call_count: dict, rate_limiter_state: Optional[dict] = None):
        conn = self._get_conn()
        try:
            rls = json.dumps(rate_limiter_state) if rate_limiter_state is not None else None
            existing = conn.execute("SELECT rate_limiter_state FROM metrics WHERE id = 1").fetchone()
            if rls is None and existing:
                rls = existing["rate_limiter_state"]
            elif rls is None:
                rls = '{}'
            conn.execute(
                """INSERT INTO metrics (id, llm_usage, call_count, rate_limiter_state) VALUES (1, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET llm_usage = excluded.llm_usage, call_count = excluded.call_count, rate_limiter_state = excluded.rate_limiter_state""",
                (json.dumps(llm_usage), json.dumps(call_count), rls),
            )
            conn.commit()
        finally:
            conn.close()

    def get_rate_limiter_state(self) -> dict:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT rate_limiter_state FROM metrics WHERE id = 1").fetchone()
            if row and row["rate_limiter_state"]:
                return json.loads(row["rate_limiter_state"])
            return {}
        finally:
            conn.close()

    def auto_title(self, conversation_id: str, query: str):
        conv = self.get_conversation(conversation_id)
        if conv and conv["title"] != "New Conversation":
            return

        INTENT_PREFIXES = {
            "check": "IOC Check",
            "is ": "IOC Check",
            "what ttp": "Actor Profile",
            "profile": "Actor Profile",
            "ttp": "Actor Profile",
            "exposed": "Exposure Check",
            "vulnerab": "Exposure Check",
            "cve": "CVE Lookup",
            "pivot": "Pivot",
            "find": "Pivot",
            "resolve": "Pivot",
            "scan": "Hash Scan",
        }
        q_lower = query.lower().strip()
        prefix = "Query"
        for keyword, label in INTENT_PREFIXES.items():
            if q_lower.startswith(keyword) or keyword in q_lower:
                prefix = label
                break
        short = query[:50] + "..." if len(query) > 50 else query
        title = f"{prefix}: {short}" if prefix != short else short
        self.update_title(conversation_id, title)
