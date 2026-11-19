import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from .analysis import family, priority


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    """One SQLite connection shared across threads (check_same_thread=False) guarded
    by a reentrant lock, so every DB access is serialised and short. Callers do their
    slow work (network I/O) OUTSIDE these methods, so the lock is only ever held for
    the brief duration of a query — reads stay responsive while a collection runs.
    WAL journaling and a busy timeout keep it robust; writes roll back on failure."""

    def __init__(self, workspace: Path):
        self.workspace = workspace
        workspace.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(workspace / "recon.db", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS runs(
          id INTEGER PRIMARY KEY, started TEXT, finished TEXT, mode TEXT,
          state TEXT, config TEXT, note TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS assets(
          host TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
          score INTEGER, reasons TEXT, sources TEXT);
        CREATE TABLE IF NOT EXISTS urls(
          url TEXT PRIMARY KEY, host TEXT, family TEXT, score INTEGER,
          reasons TEXT, sources TEXT, first_seen TEXT, last_seen TEXT, evidence TEXT);
        CREATE TABLE IF NOT EXISTS sightings(
          run_id INTEGER, kind TEXT, value TEXT,
          PRIMARY KEY(run_id,kind,value), FOREIGN KEY(run_id) REFERENCES runs(id));
        CREATE TABLE IF NOT EXISTS probes(
          run_id INTEGER, host TEXT, data TEXT,
          PRIMARY KEY(run_id,host), FOREIGN KEY(run_id) REFERENCES runs(id));
        CREATE TABLE IF NOT EXISTS changes(
          id INTEGER PRIMARY KEY, run_id INTEGER, kind TEXT, value TEXT, detail TEXT);
        CREATE INDEX IF NOT EXISTS urls_family ON urls(family);
        CREATE INDEX IF NOT EXISTS probes_host ON probes(host,run_id);
        """)
        self.db.commit()
        self._migrate_canonical_schema()
        try:
            (workspace / "recon.db").chmod(0o600)
        except OSError:
            pass

    def _migrate_canonical_schema(self):
        # Additive migration — never DROP existing tables.  Safe to run multiple
        # times (all statements use IF NOT EXISTS).  A single executescript() call
        # makes the whole batch atomic at the SQLite level.
        self.db.executescript("""
        -- Workspace: canonical workspace record keyed by uuid4
        CREATE TABLE IF NOT EXISTS workspaces(
          id TEXT PRIMARY KEY,
          name TEXT,
          slug TEXT,
          created_at TEXT,
          scope_json TEXT,
          identity_json TEXT,
          note TEXT DEFAULT ''
        );

        -- Asset: canonical asset record with uuid4 identity
        CREATE TABLE IF NOT EXISTS canon_assets(
          id TEXT PRIMARY KEY,
          workspace_id TEXT NOT NULL,
          host TEXT NOT NULL,
          first_seen TEXT,
          last_seen TEXT,
          score INTEGER,
          reasons TEXT,
          sources TEXT
        );

        -- Run: canonical run record with uuid4 identity
        CREATE TABLE IF NOT EXISTS canon_runs(
          id TEXT PRIMARY KEY,
          workspace_id TEXT NOT NULL,
          started_at TEXT,
          finished_at TEXT,
          mode TEXT,
          state TEXT,
          config_json TEXT,
          note TEXT DEFAULT ''
        );

        -- Job: scheduler job record
        CREATE TABLE IF NOT EXISTS jobs(
          id TEXT PRIMARY KEY,
          run_id TEXT,
          workspace_id TEXT NOT NULL,
          kind TEXT,
          state TEXT,
          created_at TEXT,
          started_at TEXT,
          finished_at TEXT,
          meta_json TEXT,
          error TEXT,
          requests INTEGER DEFAULT 0
        );

        -- Observation: recorded HTTP exchange with full provenance.
        -- acquisition_mode/is_probe/is_anomalous/baseline_approved added per
        -- amendment 4 (BaselineEligibilityPolicy requirements).
        CREATE TABLE IF NOT EXISTS observations(
          id TEXT PRIMARY KEY,
          workspace_id TEXT NOT NULL,
          asset_id TEXT,
          run_id TEXT,
          job_id TEXT,
          url TEXT NOT NULL,
          method TEXT NOT NULL,
          request_headers TEXT,
          request_body_hash TEXT,
          request_body_len INTEGER,
          status INTEGER,
          response_headers TEXT,
          response_body_len INTEGER,
          response_body_hash TEXT,
          elapsed_ms INTEGER,
          identity_label TEXT,
          source_engine TEXT,
          source_version TEXT,
          timestamp TEXT,
          truncated INTEGER DEFAULT 0,
          decode_lossy INTEGER DEFAULT 0,
          acquisition_mode TEXT DEFAULT 'collect',
          is_probe INTEGER DEFAULT 0,
          is_anomalous INTEGER DEFAULT 0,
          baseline_approved INTEGER DEFAULT 0
        );

        -- Finding: detector-generated candidates; verification_status is researcher-only.
        CREATE TABLE IF NOT EXISTS findings(
          id TEXT PRIMARY KEY,
          workspace_id TEXT NOT NULL,
          asset_id TEXT,
          run_id TEXT,
          source_engine TEXT,
          source_version TEXT,
          title TEXT NOT NULL,
          url TEXT NOT NULL,
          severity TEXT NOT NULL DEFAULT 'info',
          confidence REAL DEFAULT 0.5,
          heuristic_score REAL,
          ml_probability REAL,
          ml_model_id TEXT,
          verification_status TEXT DEFAULT 'unverified',
          review_status TEXT DEFAULT 'new',
          evidence_json TEXT,
          reproduction TEXT,
          remediation TEXT,
          cwe_id TEXT,
          cvss_score REAL,
          created_at TEXT,
          updated_at TEXT,
          normalization_ver TEXT
        );

        -- FindingRevision: audit trail for field-level changes to a finding
        CREATE TABLE IF NOT EXISTS finding_revisions(
          id TEXT PRIMARY KEY,
          finding_id TEXT NOT NULL,
          field_name TEXT NOT NULL,
          old_value TEXT,
          new_value TEXT,
          changed_by TEXT,
          changed_at TEXT,
          note TEXT,
          FOREIGN KEY(finding_id) REFERENCES findings(id)
        );

        -- Evidence: INSERT-only; immutability enforced at application layer.
        CREATE TABLE IF NOT EXISTS evidence(
          id TEXT PRIMARY KEY,
          workspace_id TEXT NOT NULL,
          finding_id TEXT,
          observation_id TEXT,
          kind TEXT NOT NULL,
          raw TEXT,
          summary TEXT,
          source_engine TEXT,
          source_version TEXT,
          timestamp TEXT,
          FOREIGN KEY(finding_id) REFERENCES findings(id),
          FOREIGN KEY(observation_id) REFERENCES observations(id)
        );

        -- Verification: researcher-authored confirmation or refutation record
        CREATE TABLE IF NOT EXISTS verifications(
          id TEXT PRIMARY KEY,
          finding_id TEXT NOT NULL,
          status TEXT NOT NULL,
          method TEXT,
          researcher TEXT,
          evidence_ref TEXT,
          timestamp TEXT NOT NULL,
          note TEXT,
          FOREIGN KEY(finding_id) REFERENCES findings(id)
        );

        -- ReviewEvent: INSERT-only audit trail; immutability enforced at application layer.
        CREATE TABLE IF NOT EXISTS review_events(
          id TEXT PRIMARY KEY,
          finding_id TEXT NOT NULL,
          actor TEXT,
          action TEXT NOT NULL,
          from_state TEXT,
          to_state TEXT,
          field TEXT,
          value TEXT,
          timestamp TEXT NOT NULL,
          note TEXT,
          FOREIGN KEY(finding_id) REFERENCES findings(id)
        );

        -- ModelVersion: trained model artifact metadata
        CREATE TABLE IF NOT EXISTS model_versions(
          id TEXT PRIMARY KEY,
          task TEXT NOT NULL,
          version TEXT NOT NULL,
          feature_version TEXT NOT NULL,
          dataset_version TEXT NOT NULL,
          training_config_hash TEXT,
          code_commit TEXT,
          metrics_json TEXT,
          calibration_json TEXT,
          artifact_path TEXT,
          created_at TEXT NOT NULL,
          description TEXT
        );

        -- ModelInference: INSERT-only; immutability enforced at application layer.
        -- ml_probability stays NULL until Stage 11 inference engine is deployed.
        CREATE TABLE IF NOT EXISTS model_inferences(
          id TEXT PRIMARY KEY,
          finding_id TEXT,
          observation_id TEXT,
          model_id TEXT NOT NULL,
          input_hash TEXT,
          feature_version TEXT NOT NULL,
          raw_output TEXT,
          probability REAL,
          label TEXT,
          threshold_used REAL,
          above_threshold INTEGER,
          timestamp TEXT NOT NULL,
          dataset_version TEXT,
          calibrated INTEGER DEFAULT 0,
          FOREIGN KEY(model_id) REFERENCES model_versions(id),
          FOREIGN KEY(finding_id) REFERENCES findings(id),
          FOREIGN KEY(observation_id) REFERENCES observations(id)
        );

        -- Relationship: evidence-graph edges with closed relation vocabulary
        CREATE TABLE IF NOT EXISTS relationships(
          id TEXT PRIMARY KEY,
          workspace_id TEXT NOT NULL,
          from_type TEXT NOT NULL,
          from_id TEXT NOT NULL,
          to_type TEXT NOT NULL,
          to_id TEXT NOT NULL,
          relation TEXT NOT NULL,
          confidence REAL DEFAULT 1.0,
          source TEXT,
          timestamp TEXT
        );

        -- Payload: individual payload record with risk classification
        CREATE TABLE IF NOT EXISTS payloads(
          id TEXT PRIMARY KEY,
          slug TEXT UNIQUE NOT NULL,
          description TEXT,
          risk_class TEXT NOT NULL,
          category TEXT,
          enabled INTEGER DEFAULT 1,
          raw TEXT NOT NULL,
          format TEXT,
          hash_sha256 TEXT,
          created_at TEXT NOT NULL,
          source_archive TEXT,
          source_line TEXT,
          disabled_reason TEXT
        );

        -- PayloadSet: named collection of payloads
        CREATE TABLE IF NOT EXISTS payload_sets(
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          description TEXT,
          risk_max TEXT NOT NULL,
          created_at TEXT NOT NULL
        );

        -- PayloadSetMember: junction table linking payloads to sets
        CREATE TABLE IF NOT EXISTS payload_set_members(
          payload_set_id TEXT NOT NULL,
          payload_id TEXT NOT NULL,
          PRIMARY KEY(payload_set_id, payload_id),
          FOREIGN KEY(payload_set_id) REFERENCES payload_sets(id),
          FOREIGN KEY(payload_id) REFERENCES payloads(id)
        );

        -- BaselineStore: per-(workspace, asset, url, identity) Welford statistics.
        -- UNIQUE constraint enforces the logical primary key.
        CREATE TABLE IF NOT EXISTS baseline_store(
          id TEXT PRIMARY KEY,
          workspace_id TEXT NOT NULL,
          asset_id TEXT NOT NULL,
          url_fingerprint TEXT NOT NULL,
          identity_label TEXT NOT NULL,
          sample_count INTEGER DEFAULT 0,
          body_len_mean REAL,
          body_len_m2 REAL,
          timing_mean REAL,
          timing_m2 REAL,
          status_counts TEXT,
          header_fp_counts TEXT,
          acquisition_run_id TEXT,
          last_sample_at TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(workspace_id, asset_id, url_fingerprint, identity_label)
        );

        -- LabeledObservation: human-labeled training rows with group_key for
        -- group-aware splitting (amendment 7) and synthetic flag (amendment 8).
        CREATE TABLE IF NOT EXISTS labeled_observations(
          id TEXT PRIMARY KEY,
          workspace_id TEXT,
          observation_id TEXT,
          task TEXT NOT NULL,
          label TEXT,
          group_key TEXT NOT NULL,
          synthetic INTEGER DEFAULT 0,
          labeled_by TEXT,
          labeled_at TEXT,
          note TEXT,
          FOREIGN KEY(observation_id) REFERENCES observations(id)
        );

        -- DatasetSnapshot: dataset quality gate record for a training run candidate
        CREATE TABLE IF NOT EXISTS dataset_snapshots(
          id TEXT PRIMARY KEY,
          task TEXT NOT NULL,
          snapshot_at TEXT NOT NULL,
          row_count INTEGER,
          positive_count INTEGER,
          negative_count INTEGER,
          workspace_count INTEGER,
          asset_count INTEGER,
          qualitative_gates_json TEXT,
          approved INTEGER DEFAULT 0,
          approved_by TEXT,
          approved_at TEXT
        );

        CREATE INDEX IF NOT EXISTS findings_workspace ON findings(workspace_id);
        CREATE INDEX IF NOT EXISTS findings_asset ON findings(asset_id);
        CREATE INDEX IF NOT EXISTS findings_status ON findings(verification_status, review_status);
        CREATE INDEX IF NOT EXISTS observations_workspace ON observations(workspace_id);
        CREATE INDEX IF NOT EXISTS observations_url ON observations(url, identity_label);
        CREATE INDEX IF NOT EXISTS evidence_finding ON evidence(finding_id);
        CREATE INDEX IF NOT EXISTS review_events_finding ON review_events(finding_id);
        CREATE INDEX IF NOT EXISTS model_inferences_finding ON model_inferences(finding_id);
        CREATE INDEX IF NOT EXISTS model_inferences_obs ON model_inferences(observation_id);
        CREATE INDEX IF NOT EXISTS relationships_from ON relationships(from_type, from_id);
        CREATE INDEX IF NOT EXISTS relationships_to ON relationships(to_type, to_id);
        CREATE INDEX IF NOT EXISTS labeled_obs_task ON labeled_observations(task, group_key);
        CREATE INDEX IF NOT EXISTS baseline_store_key ON baseline_store(workspace_id, asset_id, url_fingerprint, identity_label);
        """)
        # Database-level immutability enforcement and value constraints.
        # Separate executescript so BEGIN...END trigger syntax is parsed cleanly.
        self.db.executescript("""
        CREATE TRIGGER IF NOT EXISTS evidence_no_update
          BEFORE UPDATE ON evidence
        BEGIN SELECT RAISE(ABORT, 'evidence rows are INSERT-only'); END;

        CREATE TRIGGER IF NOT EXISTS evidence_no_delete
          BEFORE DELETE ON evidence
        BEGIN SELECT RAISE(ABORT, 'evidence rows are INSERT-only'); END;

        CREATE TRIGGER IF NOT EXISTS review_events_no_update
          BEFORE UPDATE ON review_events
        BEGIN SELECT RAISE(ABORT, 'review_events rows are INSERT-only'); END;

        CREATE TRIGGER IF NOT EXISTS review_events_no_delete
          BEFORE DELETE ON review_events
        BEGIN SELECT RAISE(ABORT, 'review_events rows are INSERT-only'); END;

        CREATE TRIGGER IF NOT EXISTS model_inferences_no_update
          BEFORE UPDATE ON model_inferences
        BEGIN SELECT RAISE(ABORT, 'model_inferences rows are INSERT-only'); END;

        CREATE TRIGGER IF NOT EXISTS model_inferences_no_delete
          BEFORE DELETE ON model_inferences
        BEGIN SELECT RAISE(ABORT, 'model_inferences rows are INSERT-only'); END;

        CREATE TRIGGER IF NOT EXISTS mi_prob_check
          BEFORE INSERT ON model_inferences
          WHEN NEW.probability IS NOT NULL AND (NEW.probability < 0.0 OR NEW.probability > 1.0)
        BEGIN SELECT RAISE(ABORT, 'model_inferences.probability must be in [0,1]'); END;

        CREATE TRIGGER IF NOT EXISTS finding_ml_prob_insert
          BEFORE INSERT ON findings
          WHEN NEW.ml_probability IS NOT NULL AND (NEW.ml_probability < 0.0 OR NEW.ml_probability > 1.0)
        BEGIN SELECT RAISE(ABORT, 'findings.ml_probability must be in [0,1]'); END;

        CREATE TRIGGER IF NOT EXISTS finding_ml_prob_update
          BEFORE UPDATE ON findings
          WHEN NEW.ml_probability IS NOT NULL AND (NEW.ml_probability < 0.0 OR NEW.ml_probability > 1.0)
        BEGIN SELECT RAISE(ABORT, 'findings.ml_probability must be in [0,1]'); END;

        CREATE TRIGGER IF NOT EXISTS finding_confidence_insert
          BEFORE INSERT ON findings
          WHEN NEW.confidence IS NOT NULL AND (NEW.confidence < 0.0 OR NEW.confidence > 1.0)
        BEGIN SELECT RAISE(ABORT, 'findings.confidence must be in [0,1]'); END;

        CREATE TRIGGER IF NOT EXISTS finding_confidence_update
          BEFORE UPDATE ON findings
          WHEN NEW.confidence IS NOT NULL AND (NEW.confidence < 0.0 OR NEW.confidence > 1.0)
        BEGIN SELECT RAISE(ABORT, 'findings.confidence must be in [0,1]'); END;
        """)
        # Additive columns: the finding generator emits observation_id/description but
        # the table had no such columns, so they were silently dropped and a human
        # review label could never be linked back to its observation.
        have = {r[1] for r in self.db.execute("PRAGMA table_info(findings)").fetchall()}
        for col in ("observation_id", "description"):
            if col not in have:
                self.db.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT")
        self.db.commit()

    def start(self, mode: str, config: dict):
        # Do not retain header values in run history/exports.
        config = {**config, "headers": sorted(config.get("headers", {}))}
        with self._lock:
            try:
                cur = self.db.execute(
                    "INSERT INTO runs(started,mode,state,config) VALUES(?,?,?,?)",
                    (now(), mode, "running", json.dumps(config)),
                )
                self.db.commit()
                return cur.lastrowid
            except Exception:
                self.db.rollback()
                raise

    def finish(self, run_id, state="complete", note=""):
        with self._lock:
            try:
                self.db.execute("UPDATE runs SET state=?,finished=?,note=? WHERE id=?", (state, now(), note, run_id))
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise

    def change(self, run_id, kind, value, detail):
        # No commit — batched with the surrounding upsert; caller commits.
        with self._lock:
            self.db.execute("INSERT INTO changes(run_id,kind,value,detail) VALUES(?,?,?,?)", (run_id, kind, value, detail))

    def _upsert(self, table, key, value, source, run_id, extras=None):
        with self._lock:
            old = self.db.execute(f"SELECT sources FROM {table} WHERE {key}=?", (value,)).fetchone()
            sources = set(json.loads(old[0])) if old else set()
            sources.add(source)
            stamp = now()
            score, reasons = priority(value)
            if old:
                self.db.execute(f"UPDATE {table} SET sources=?,last_seen=? WHERE {key}=?", (json.dumps(sorted(sources)), stamp, value))
            else:
                fields = {key: value, "score": score, "reasons": json.dumps(reasons),
                          "sources": json.dumps(sorted(sources)), "first_seen": stamp, "last_seen": stamp,
                          **(extras or {})}
                columns = ",".join(fields)
                self.db.execute(f"INSERT INTO {table}({columns}) VALUES({','.join('?' for _ in fields)})", tuple(fields.values()))
                self.change(run_id, "new " + key, value, "First observed via " + source)
            self.db.execute("INSERT OR IGNORE INTO sightings VALUES(?,?,?)", (run_id, key, value))
            return old is None

    def host(self, host, source, run_id):
        with self._lock:
            return self._upsert("assets", "host", host, source, run_id)

    def url(self, url, source, run_id, evidence=None):
        from urllib.parse import urlsplit
        host = urlsplit(url).hostname
        with self._lock:
            self.host(host, source, run_id)
            fresh = self._upsert("urls", "url", url, source, run_id, {
                "host": host, "family": family(url), "evidence": json.dumps(evidence or {}),
            })
            if evidence:
                self.db.execute("UPDATE urls SET evidence=? WHERE url=?", (json.dumps(evidence), url))
            return fresh

    def probe(self, host, data, run_id):
        with self._lock:
            try:
                previous = self.db.execute("SELECT data FROM probes WHERE host=? ORDER BY run_id DESC LIMIT 1", (host,)).fetchone()
                if previous:
                    old = json.loads(previous[0])
                    changes = [key for key in ("status", "title", "server", "final_url", "body_hash", "error")
                               if old.get(key) != data.get(key)]
                    if changes:
                        self.change(run_id, "HTTP changed", host, ", ".join(changes))
                self.db.execute("INSERT OR REPLACE INTO probes VALUES(?,?,?)", (run_id, host, json.dumps(data)))
                score, reasons = priority(host, data.get("status"))
                self.db.execute("UPDATE assets SET score=?,reasons=? WHERE host=?", (score, json.dumps(reasons), host))
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise

    def last_probe_runs(self):
        """{host: latest run_id that probed it} — used to rotate the probe cap."""
        with self._lock:
            return {r[0]: r[1] for r in self.db.execute(
                "SELECT host, MAX(run_id) FROM probes GROUP BY host").fetchall()}

    def assets(self):
        with self._lock:
            rows = self.db.execute("""SELECT a.*, p.data AS probe FROM assets a
                LEFT JOIN probes p ON p.host=a.host AND p.run_id=(SELECT MAX(q.run_id) FROM probes q WHERE q.host=a.host)
                ORDER BY a.score DESC,a.host""").fetchall()
            result = []
            for row in rows:
                record = dict(row)
                record["probe"] = json.loads(record["probe"]) if record["probe"] else {}
                for field in ("sources", "reasons"):
                    record[field] = json.loads(record[field])
                result.append(record)
            return result

    def urls(self):
        with self._lock:
            result = []
            for row in self.db.execute("SELECT * FROM urls ORDER BY score DESC,url").fetchall():
                record = dict(row)
                for key in ("sources", "reasons", "evidence"):
                    record[key] = json.loads(record[key])
                result.append(record)
            return result

    def changes(self, limit=1000):
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM changes ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

    def runs(self):
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM runs ORDER BY id DESC").fetchall()]

    def mark_interrupted(self, exclude_run_ids=()):
        """Crash recovery: any run left in 'running' from a previous process (killed
        mid-collection) is marked 'interrupted' when the workspace is next opened.
        State-changing work is NOT auto-replayed — the user decides whether to re-run.
        Returns the number of runs recovered."""
        with self._lock:
            try:
                active = tuple(exclude_run_ids)
                exclude = (" AND id NOT IN (" + ",".join("?" for _ in active) + ")") if active else ""
                cur = self.db.execute(
                    "UPDATE runs SET state='interrupted', finished=?, "
                    "note=CASE WHEN note='' THEN 'recovered on startup' "
                    "ELSE note || ' | recovered on startup' END WHERE state='running'" + exclude,
                    (now(), *active),
                )
                self.db.commit()
                return cur.rowcount
            except Exception:
                self.db.rollback()
                raise

    def integrity_check(self):
        with self._lock:
            row = self.db.execute("PRAGMA integrity_check").fetchone()
            return row[0] if row else "unknown"

    def commit(self):
        with self._lock:
            self.db.commit()

    # ------------------------------------------------------------------
    # Canonical V5 persistence methods
    # ------------------------------------------------------------------

    def save_observation(self, obs: dict) -> None:
        cols = (
            "id", "workspace_id", "asset_id", "run_id", "job_id", "url", "method",
            "request_headers", "request_body_hash", "request_body_len", "status",
            "response_headers", "response_body_len", "response_body_hash",
            "elapsed_ms", "identity_label", "source_engine", "source_version",
            "timestamp", "truncated", "decode_lossy", "acquisition_mode",
            "is_probe", "is_anomalous", "baseline_approved",
        )
        with self._lock:
            try:
                vals = tuple(obs.get(c) for c in cols)
                ph = ",".join("?" for _ in cols)
                self.db.execute(f"INSERT OR IGNORE INTO observations({','.join(cols)}) VALUES({ph})", vals)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise

    def get_observations(self, workspace_id: str, limit: int = 100, offset: int = 0) -> list:
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM observations WHERE workspace_id=? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (workspace_id, limit, offset),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_observation(self, obs_id: str, workspace_id: str) -> dict | None:
        with self._lock:
            row = self.db.execute(
                "SELECT * FROM observations WHERE id=? AND workspace_id=?",
                (obs_id, workspace_id),
            ).fetchone()
            return dict(row) if row else None

    def save_finding(self, finding: dict) -> None:
        cols = (
            "id", "workspace_id", "asset_id", "run_id", "source_engine",
            "source_version", "title", "url", "severity", "confidence",
            "heuristic_score", "ml_probability", "ml_model_id",
            "verification_status", "review_status", "evidence_json",
            "reproduction", "remediation", "cwe_id", "cvss_score",
            "created_at", "updated_at", "normalization_ver",
            "observation_id", "description",
        )
        with self._lock:
            try:
                vals = tuple(finding.get(c) for c in cols)
                ph = ",".join("?" for _ in cols)
                self.db.execute(f"INSERT OR IGNORE INTO findings({','.join(cols)}) VALUES({ph})", vals)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise

    def get_findings(self, workspace_id: str, limit: int = 100, offset: int = 0,
                     review_status: str = None, verification_status: str = None) -> list:
        with self._lock:
            base = "SELECT * FROM findings WHERE workspace_id=?"
            params: list = [workspace_id]
            if review_status:
                base += " AND review_status=?"
                params.append(review_status)
            if verification_status:
                base += " AND verification_status=?"
                params.append(verification_status)
            base += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params += [limit, offset]
            return [dict(r) for r in self.db.execute(base, params).fetchall()]

    def get_finding(self, finding_id: str, workspace_id: str) -> dict | None:
        with self._lock:
            row = self.db.execute(
                "SELECT * FROM findings WHERE id=? AND workspace_id=?",
                (finding_id, workspace_id),
            ).fetchone()
            return dict(row) if row else None

    def update_finding(self, finding_id: str, workspace_id: str, updates: dict) -> bool:
        allowed = {"title", "severity", "reproduction", "remediation", "cwe_id",
                   "review_status", "verification_status", "updated_at"}
        safe = {k: v for k, v in updates.items() if k in allowed}
        if not safe:
            return False
        with self._lock:
            try:
                set_clause = ",".join(f"{k}=?" for k in safe)
                vals = list(safe.values()) + [finding_id, workspace_id]
                cur = self.db.execute(
                    f"UPDATE findings SET {set_clause} WHERE id=? AND workspace_id=?", vals
                )
                self.db.commit()
                return cur.rowcount > 0
            except Exception:
                self.db.rollback()
                raise

    def save_evidence(self, evidence: dict) -> None:
        cols = ("id", "workspace_id", "finding_id", "observation_id", "kind",
                "raw", "summary", "source_engine", "source_version", "timestamp")
        with self._lock:
            try:
                vals = tuple(evidence.get(c) for c in cols)
                ph = ",".join("?" for _ in cols)
                self.db.execute(f"INSERT OR IGNORE INTO evidence({','.join(cols)}) VALUES({ph})", vals)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise

    def get_evidence(self, finding_id: str, workspace_id: str) -> list:
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM evidence WHERE finding_id=? AND workspace_id=? ORDER BY timestamp",
                (finding_id, workspace_id),
            ).fetchall()
            return [dict(r) for r in rows]

    def save_review_event(self, event: dict) -> None:
        cols = ("id", "finding_id", "actor", "action", "from_state", "to_state",
                "field", "value", "timestamp", "note")
        with self._lock:
            try:
                vals = tuple(event.get(c) for c in cols)
                ph = ",".join("?" for _ in cols)
                self.db.execute(f"INSERT OR IGNORE INTO review_events({','.join(cols)}) VALUES({ph})", vals)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise

    def get_review_events(self, finding_id: str, workspace_id: str) -> list:
        with self._lock:
            rows = self.db.execute(
                """SELECT re.* FROM review_events re
                   JOIN findings f ON f.id=re.finding_id
                   WHERE re.finding_id=? AND f.workspace_id=?
                   ORDER BY re.timestamp""",
                (finding_id, workspace_id),
            ).fetchall()
            return [dict(r) for r in rows]

    def save_relationship(self, rel: dict) -> None:
        cols = ("id", "workspace_id", "from_type", "from_id", "to_type",
                "to_id", "relation", "confidence", "source", "timestamp")
        with self._lock:
            try:
                vals = tuple(rel.get(c) for c in cols)
                ph = ",".join("?" for _ in cols)
                self.db.execute(f"INSERT OR IGNORE INTO relationships({','.join(cols)}) VALUES({ph})", vals)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise

    def get_relationships(self, workspace_id: str, entity_type: str = None,
                          entity_id: str = None) -> list:
        with self._lock:
            if entity_id and entity_type:
                rows = self.db.execute(
                    """SELECT * FROM relationships WHERE workspace_id=?
                       AND ((from_type=? AND from_id=?) OR (to_type=? AND to_id=?))
                       ORDER BY timestamp""",
                    (workspace_id, entity_type, entity_id, entity_type, entity_id),
                ).fetchall()
            else:
                rows = self.db.execute(
                    "SELECT * FROM relationships WHERE workspace_id=? ORDER BY timestamp",
                    (workspace_id,),
                ).fetchall()
            return [dict(r) for r in rows]

    def get_baseline(self, workspace_id: str, asset_id: str,
                     url_fingerprint: str, identity_label: str) -> dict | None:
        with self._lock:
            row = self.db.execute(
                """SELECT * FROM baseline_store
                   WHERE workspace_id=? AND asset_id=? AND url_fingerprint=? AND identity_label=?""",
                (workspace_id, asset_id, url_fingerprint, identity_label),
            ).fetchone()
            return dict(row) if row else None

    def list_baselines(self, workspace_id: str) -> list:
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM baseline_store WHERE workspace_id=? ORDER BY updated_at DESC",
                (workspace_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def save_baseline(self, baseline: dict) -> None:
        cols = (
            "id", "workspace_id", "asset_id", "url_fingerprint", "identity_label",
            "sample_count", "body_len_mean", "body_len_m2", "timing_mean", "timing_m2",
            "status_counts", "header_fp_counts", "acquisition_run_id",
            "last_sample_at", "created_at", "updated_at",
        )
        with self._lock:
            try:
                existing = self.db.execute(
                    """SELECT id FROM baseline_store
                       WHERE workspace_id=? AND asset_id=? AND url_fingerprint=? AND identity_label=?""",
                    (baseline.get("workspace_id"), baseline.get("asset_id"),
                     baseline.get("url_fingerprint"), baseline.get("identity_label")),
                ).fetchone()
                if existing:
                    update_cols = [c for c in cols if c not in
                                   ("id", "workspace_id", "asset_id", "url_fingerprint",
                                    "identity_label", "created_at")]
                    set_clause = ",".join(f"{c}=?" for c in update_cols)
                    vals = [baseline.get(c) for c in update_cols] + [existing[0]]
                    self.db.execute(f"UPDATE baseline_store SET {set_clause} WHERE id=?", vals)
                else:
                    vals = tuple(baseline.get(c) for c in cols)
                    ph = ",".join("?" for _ in cols)
                    self.db.execute(f"INSERT INTO baseline_store({','.join(cols)}) VALUES({ph})", vals)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise

    def save_labeled_observation(self, row: dict) -> None:
        """INSERT a labeled observation row for dataset construction.

        Maps the LabelStore.to_db_row() 'labeler' key to the schema's
        'labeled_by' column.  Silently absorbs duplicate-id conflicts.
        """
        with self._lock:
            try:
                self.db.execute(
                    """INSERT OR IGNORE INTO labeled_observations
                       (id, workspace_id, observation_id, task, label,
                        group_key, synthetic, labeled_by, labeled_at, note)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        row.get("id"), row.get("workspace_id"),
                        row.get("observation_id"), row.get("task"),
                        row.get("label"), row.get("group_key"),
                        int(row.get("synthetic", 0)),
                        row.get("labeler") or row.get("labeled_by"),
                        row.get("labeled_at"), row.get("note", ""),
                    ),
                )
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise

    def count_findings(self, workspace_id: str) -> int:
        with self._lock:
            row = self.db.execute(
                "SELECT COUNT(*) FROM findings WHERE workspace_id=?", (workspace_id,)
            ).fetchone()
            return row[0] if row else 0

    def get_workspace_id(self) -> str | None:
        """Return the canonical workspace UUID if one exists for this workspace path."""
        with self._lock:
            row = self.db.execute(
                "SELECT id FROM workspaces ORDER BY created_at LIMIT 1"
            ).fetchone()
            return row[0] if row else None

    def ensure_workspace_record(self, workspace_id: str, name: str, scope_json: str = None) -> None:
        """Idempotent: insert a workspace record if none exists."""
        with self._lock:
            try:
                existing = self.db.execute(
                    "SELECT id FROM workspaces WHERE id=?", (workspace_id,)
                ).fetchone()
                if not existing:
                    self.db.execute(
                        "INSERT OR IGNORE INTO workspaces(id, name, created_at, scope_json) VALUES(?,?,?,?)",
                        (workspace_id, name, now(), scope_json),
                    )
                    self.db.commit()
            except Exception:
                self.db.rollback()
                raise

    def close(self):
        with self._lock:
            if getattr(self, "_closed", False):
                return
            self._closed = True
            try:
                self.db.commit()
            finally:
                self.db.close()
