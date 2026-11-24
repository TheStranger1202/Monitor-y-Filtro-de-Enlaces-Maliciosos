"""
Suite de pruebas funcionales y de seguridad (OWASP + Edge Cases) para la Etapa 1.
Valida:
- Ausencia total de clases POO en los módulos desarrollados
- Inmutabilidad de datos y encapsulamiento léxico de secretos
- EC-LOG-01: Sanitización contra Log Injection (CRLF y nulos)
- EC-XSS-02: Detección de esquemas peligrosos y Defanging de URLs
- EC-DB-01: Resistencia total a SQL Injection
- EC-DB-02: Idempotencia ante Message-ID duplicados
- EC-DB-03: Activación de modo WAL y acceso concurrente en SQLite
"""

import ast
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest

from app.core.config import build_config_from_mapping
from app.core.security import (
    defang_url,
    get_owasp_security_headers,
    has_dangerous_scheme,
    sanitize_for_log,
)
from app.core.types import UrlVerdict, make_secret
from app.db.database import (
    fetch_whitelisted_domains,
    get_dashboard_stats,
    init_database,
    insert_threat_feed_batch,
    is_email_already_processed,
    is_url_or_domain_blacklisted,
    list_recent_emails,
    open_db_connection,
    save_email_analysis,
)


def test_zero_oop_classes_in_codebase() -> None:
    """Garantiza por análisis AST que ningún archivo de app/ contiene `class ...`."""
    files_to_audit = (
        Path("app/core/types.py"),
        Path("app/core/config.py"),
        Path("app/core/security.py"),
        Path("app/db/database.py"),
    )
    for file_path in files_to_audit:
        tree = ast.parse(file_path.read_text(encoding="utf-8"))
        class_defs = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        assert class_defs == [], f"Se detectó una clase prohibida en {file_path}"


def test_secret_closure_never_leaks_and_config_is_immutable() -> None:
    """Verifica que las contraseñas no se filtren en repr/str y que AppConfig sea inmutable."""
    secret = make_secret("SuperClaveSecreta123!")
    assert "SuperClaveSecreta123!" not in repr(secret)
    assert "SuperClaveSecreta123!" not in str(secret)
    assert secret.masked == "********"
    assert secret.reveal() == "SuperClaveSecreta123!"

    cfg = build_config_from_mapping(
        {
            "EMAIL_USER": "aduanas@empresa-chacao.com",
            "EMAIL_PASSWORD": "clave_app_secreta",
            "VIRUSTOTAL_API_KEY": "vt_api_secreta",
        }
    )
    assert "clave_app_secreta" not in repr(cfg)
    assert "vt_api_secreta" not in repr(cfg)
    assert cfg.email_password.reveal() == "clave_app_secreta"

    with pytest.raises(AttributeError):
        cfg.imap_port = 143  # type: ignore[misc]


def test_config_rejects_unsafe_values() -> None:
    """Verifica rechazo temprano de configuraciones fuera de rango o con CRLF injection."""
    with pytest.raises(ValueError):
        build_config_from_mapping({"CHECK_INTERVAL_SECONDS": "2"})  # Menor al mínimo anti-ban (10s)

    with pytest.raises(ValueError):
        build_config_from_mapping({"QUARANTINE_FOLDER": "Cuarentena\r\nDELETE INBOX"})

    with pytest.raises(ValueError):
        build_config_from_mapping(
            {"RISK_THRESHOLD_SUSPICIOUS": "80", "RISK_THRESHOLD_QUARANTINE": "60"}
        )


def test_ec_log_01_and_ec_xss_02_security_helpers() -> None:
    """Valida sanitización anti-Log Injection (EC-LOG-01), esquemas XSS (EC-XSS-02) y CSP."""
    forged_input = "Asunto normal\r\n2026-11-24 [INFO] Usuario admin autenticado\x00"
    sanitized = sanitize_for_log(forged_input)
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert "\x00" not in sanitized

    assert has_dangerous_scheme("  JaVaScRiPt:alert(document.cookie)") is True
    assert has_dangerous_scheme("data:text/html;base64,PHNjcmlwdD4=") is True
    assert has_dangerous_scheme("https://seniat.gob.ve") is False

    defanged = defang_url("https://dhl-tracking.evil.com/guia")
    assert defanged == "hxxps://dhl-tracking[.]evil[.]com/guia"
    assert defang_url("javascript:alert(1)") == "blocked-javascript:alert(1)"

    headers = dict(get_owasp_security_headers())
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_ec_db_01_sql_injection_and_ec_db_02_idempotency(tmp_path: Path) -> None:
    """Somete SQLite a payloads de SQL Injection (EC-DB-01) y correos duplicados (EC-DB-02)."""
    db_file = str(tmp_path / "test_sec.db")
    init_database(db_file)

    sqli_url = "http://evil-aduanas.com/bill?id=1' OR '1'='1'); DROP TABLE processed_emails;--"
    sqli_subject = "Factura '; DELETE FROM whitelisted_domains WHERE '1'='1"

    sample_verdict = UrlVerdict(
        original_url=sqli_url,
        defanged_url=defang_url(sqli_url),
        visible_text="Ver factura",
        domain="evil-aduanas.com",
        layer1_status="BLACKLISTED",
        vt_malicious_count=5,
        vt_suspicious_count=1,
        heuristic_score=40,
        heuristic_reasons=("customs_keyword", "blacklisted_feed"),
        final_score=100,
        verdict="MALICIOUS",
    )

    with open_db_connection(db_file) as conn:
        whitelist = fetch_whitelisted_domains(conn)
        assert "seniat.gob.ve" in whitelist
        assert "maersk.com" in whitelist

        inserted = insert_threat_feed_batch(
            conn, [(sqli_url, "evil-aduanas.com", "phishing", "urlhaus")]
        )
        assert inserted == 1
        assert is_url_or_domain_blacklisted(conn, sqli_url, "no-existe.com") is True

        first_id = save_email_analysis(
            conn=conn,
            message_id="<msg-001@naviera.com>",
            sender="atacante@evil-aduanas.com",
            subject=sqli_subject,
            max_risk_score=100,
            status="QUARANTINED",
            quarantined=True,
            verdicts=(sample_verdict,),
        )
        assert first_id is not None
        assert is_email_already_processed(conn, "<msg-001@naviera.com>") is True

        # EC-DB-02: Reintento con el mismo Message-ID no debe duplicar registros
        duplicate_id = save_email_analysis(
            conn=conn,
            message_id="<msg-001@naviera.com>",
            sender="atacante@evil-aduanas.com",
            subject=sqli_subject,
            max_risk_score=100,
            status="QUARANTINED",
            quarantined=True,
            verdicts=(sample_verdict,),
        )
        assert duplicate_id is None

        # Comprobar que las tablas y la whitelist siguen intactas tras el intento de SQLi
        assert len(fetch_whitelisted_domains(conn)) >= 20
        stats = get_dashboard_stats(conn)
        assert stats.total_emails == 1
        assert stats.quarantined_emails == 1
        assert stats.total_malicious_urls == 1

        recent = list_recent_emails(conn, limit=10)
        assert len(recent) == 1
        assert recent[0].subject == sqli_subject


def test_ec_db_03_wal_mode_and_concurrent_access(tmp_path: Path) -> None:
    """Comprueba modo WAL activo y lecturas/escrituras simultáneas sin bloqueo (EC-DB-03)."""
    db_file = str(tmp_path / "test_wal.db")
    init_database(db_file)

    with open_db_connection(db_file) as conn:
        mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert str(mode).lower() == "wal"

    def _worker(idx: int) -> bool:
        with open_db_connection(db_file) as c:
            save_email_analysis(
                conn=c,
                message_id=f"<concurrent-{idx}@chacao.ve>",
                sender="proveedor@maersk.com",
                subject=f"BL #{idx}",
                max_risk_score=0,
                status="CLEAN",
                quarantined=False,
                verdicts=(),
            )
            stats = get_dashboard_stats(c)
            return stats.total_emails >= 1

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(_worker, range(12)))

    assert all(results)
    with open_db_connection(db_file) as conn:
        assert get_dashboard_stats(conn).total_emails == 12
