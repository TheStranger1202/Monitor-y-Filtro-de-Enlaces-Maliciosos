"""
Capa de persistencia funcional sobre sqlite3 nativo (Cero ORM / Cero POO).
Implementa modo WAL para concurrencia segura y consultas 100% parametrizadas (OWASP A03).
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional, Sequence
from app.core.types import DashboardStats, EmailRecord, UrlVerdict

DEFAULT_WHITELIST: tuple[tuple[str, str], ...] = (
    ("google.com", "general"),
    ("gmail.com", "general"),
    ("microsoft.com", "general"),
    ("outlook.com", "general"),
    ("w3.org", "general"),
    ("schema.org", "general"),
    ("linkedin.com", "social"),
    ("instagram.com", "social"),
    ("facebook.com", "social"),
    ("x.com", "social"),
    ("twitter.com", "social"),
    ("youtube.com", "social"),
    ("seniat.gob.ve", "customs"),
    ("bolipuertos.gob.ve", "customs"),
    ("maersk.com", "logistics"),
    ("msc.com", "logistics"),
    ("cma-cgm.com", "logistics"),
    ("hapag-lloyd.com", "logistics"),
    ("dhl.com", "logistics"),
    ("fedex.com", "logistics"),
    ("ups.com", "logistics"),
    ("grupozoom.com", "logistics"),
    ("tealca.com", "logistics"),
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS processed_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL UNIQUE,
    sender TEXT NOT NULL,
    subject TEXT NOT NULL,
    received_at TEXT NOT NULL,
    processed_at TEXT NOT NULL,
    max_risk_score INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'CLEAN',
    quarantined INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_emails_status ON processed_emails(status);
CREATE INDEX IF NOT EXISTS idx_emails_processed_at ON processed_emails(processed_at DESC);

CREATE TABLE IF NOT EXISTS analyzed_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER,
    original_url TEXT NOT NULL,
    defanged_url TEXT NOT NULL,
    visible_text TEXT,
    domain TEXT NOT NULL,
    layer1_status TEXT NOT NULL,
    vt_malicious_count INTEGER NOT NULL DEFAULT 0,
    vt_suspicious_count INTEGER NOT NULL DEFAULT 0,
    heuristic_score INTEGER NOT NULL DEFAULT 0,
    heuristic_reasons TEXT NOT NULL DEFAULT '',
    final_score INTEGER NOT NULL DEFAULT 0,
    verdict TEXT NOT NULL,
    analyzed_at TEXT NOT NULL,
    FOREIGN KEY (email_id) REFERENCES processed_emails(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_urls_domain ON analyzed_urls(domain);
CREATE INDEX IF NOT EXISTS idx_urls_verdict ON analyzed_urls(verdict);

CREATE TABLE IF NOT EXISTS threat_feeds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    threat_type TEXT NOT NULL DEFAULT 'phishing',
    source TEXT NOT NULL DEFAULT 'urlhaus',
    added_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feeds_domain ON threat_feeds(domain);

CREATE TABLE IF NOT EXISTS whitelisted_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL DEFAULT 'general',
    added_at TEXT NOT NULL
);
"""


def utc_now_iso() -> str:
    """Retorna el timestamp actual en UTC ISO-8601."""
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def open_db_connection(db_path: str) -> Iterator[sqlite3.Connection]:
    """
    Gestor de contexto funcional que abre una conexión SQLite con modo WAL,
    claves foráneas activas y timeout de concurrencia (mitiga EC-DB-03).
    """
    conn = sqlite3.connect(db_path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_database(db_path: str) -> None:
    """Inicializa el esquema relacional y precarga de forma idempotente la Lista Blanca."""
    now = utc_now_iso()
    with open_db_connection(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.executemany(
            "INSERT OR IGNORE INTO whitelisted_domains (domain, category, added_at) VALUES (?, ?, ?)",
            [(domain.lower(), category, now) for domain, category in DEFAULT_WHITELIST],
        )


def is_email_already_processed(conn: sqlite3.Connection, message_id: str) -> bool:
    """Verifica por Message-ID si un correo ya fue analizado previamente (EC-DB-02)."""
    row = conn.execute(
        "SELECT 1 FROM processed_emails WHERE message_id = ? LIMIT 1",
        (message_id.strip(),),
    ).fetchone()
    return row is not None


def fetch_whitelisted_domains(conn: sqlite3.Connection) -> frozenset[str]:
    """Retorna un conjunto inmutable (`frozenset`) con todos los dominios en Lista Blanca."""
    rows = conn.execute("SELECT domain FROM whitelisted_domains").fetchall()
    return frozenset(str(r["domain"]).lower() for r in rows)


def is_url_or_domain_blacklisted(conn: sqlite3.Connection, url: str, domain: str) -> bool:
    """Consulta parametrizada contra la tabla local de amenazas `threat_feeds`."""
    row = conn.execute(
        "SELECT 1 FROM threat_feeds WHERE url = ? OR domain = ? LIMIT 1",
        (url.strip(), domain.strip().lower()),
    ).fetchone()
    return row is not None


def insert_threat_feed_batch(
    conn: sqlite3.Connection, entries: Sequence[tuple[str, str, str, str]]
) -> int:
    """
    Inserta de forma transaccional un lote de amenazas `(url, domain, threat_type, source)`.
    Retorna la cantidad de filas nuevas insertadas.
    """
    now = utc_now_iso()
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO threat_feeds (url, domain, threat_type, source, added_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        [(u.strip(), d.strip().lower(), t.strip(), s.strip(), now) for u, d, t, s in entries],
    )
    return conn.total_changes - before


def save_email_analysis(
    conn: sqlite3.Connection,
    message_id: str,
    sender: str,
    subject: str,
    max_risk_score: int,
    status: str,
    quarantined: bool,
    verdicts: Sequence[UrlVerdict],
    received_at: Optional[str] = None,
) -> Optional[int]:
    """
    Registra de forma atómica un correo procesado y todos sus enlaces analizados.
    Si `message_id` ya existe (EC-DB-02), ignora el duplicado y devuelve None.
    """
    now = utc_now_iso()
    recv_ts = received_at or now

    cursor = conn.execute(
        """
        INSERT OR IGNORE INTO processed_emails
            (message_id, sender, subject, received_at, processed_at, max_risk_score, status, quarantined)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            message_id.strip()[:512],
            sender.strip()[:320],
            subject.strip()[:998],
            recv_ts,
            now,
            int(max_risk_score),
            status,
            1 if quarantined else 0,
        ),
    )
    if cursor.rowcount == 0:
        return None

    email_id = int(cursor.lastrowid)
    save_url_verdicts(conn, verdicts, email_id=email_id)
    return email_id


def save_url_verdicts(
    conn: sqlite3.Connection,
    verdicts: Sequence[UrlVerdict],
    email_id: Optional[int] = None,
) -> None:
    """Guarda una secuencia de `UrlVerdict` (asociados a un correo o del analizador manual)."""
    now = utc_now_iso()
    conn.executemany(
        """
        INSERT INTO analyzed_urls (
            email_id, original_url, defanged_url, visible_text, domain,
            layer1_status, vt_malicious_count, vt_suspicious_count,
            heuristic_score, heuristic_reasons, final_score, verdict, analyzed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                email_id,
                v.original_url[:2048],
                v.defanged_url[:2100],
                (v.visible_text or "")[:512],
                v.domain[:255],
                v.layer1_status,
                int(v.vt_malicious_count),
                int(v.vt_suspicious_count),
                int(v.heuristic_score),
                "|".join(v.heuristic_reasons)[:1024],
                int(v.final_score),
                v.verdict,
                now,
            )
            for v in verdicts
        ],
    )


def get_dashboard_stats(conn: sqlite3.Connection) -> DashboardStats:
    """Calcula métricas agregadas inmutables para el Panel de Control."""
    email_row = conn.execute(
        """
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN status = 'CLEAN' THEN 1 ELSE 0 END), 0) AS clean,
            COALESCE(SUM(CASE WHEN status = 'SUSPICIOUS' THEN 1 ELSE 0 END), 0) AS suspicious,
            COALESCE(SUM(CASE WHEN quarantined = 1 THEN 1 ELSE 0 END), 0) AS quarantined
        FROM processed_emails
        """
    ).fetchone()

    url_row = conn.execute(
        "SELECT COUNT(*) AS malicious_urls FROM analyzed_urls WHERE verdict = 'MALICIOUS'"
    ).fetchone()

    return DashboardStats(
        total_emails=int(email_row["total"]),
        clean_emails=int(email_row["clean"]),
        suspicious_emails=int(email_row["suspicious"]),
        quarantined_emails=int(email_row["quarantined"]),
        total_malicious_urls=int(url_row["malicious_urls"]),
    )


def list_recent_emails(conn: sqlite3.Connection, limit: int = 50) -> tuple[EmailRecord, ...]:
    """Devuelve una tupla inmutable con los últimos correos analizados (límite acotado)."""
    safe_limit = max(1, min(int(limit), 200))
    rows = conn.execute(
        """
        SELECT id, message_id, sender, subject, received_at, processed_at,
               max_risk_score, status, quarantined
        FROM processed_emails
        ORDER BY id DESC
        LIMIT ?
        """,
        (safe_limit,),
    ).fetchall()

    return tuple(
        EmailRecord(
            id=int(r["id"]),
            message_id=str(r["message_id"]),
            sender=str(r["sender"]),
            subject=str(r["subject"]),
            received_at=str(r["received_at"]),
            processed_at=str(r["processed_at"]),
            max_risk_score=int(r["max_risk_score"]),
            status=str(r["status"]),
            quarantined=bool(r["quarantined"]),
        )
        for r in rows
    )
