"""
Suite de pruebas funcionales y de seguridad (OWASP + Edge Cases) para la Etapa 3.
Valida:
- Auditoría AST en todos los archivos de la Etapa 3
- EC-EXT-01..03: Resiliencia ante VirusTotal 429, Timeouts, 404 y JSON corrupto + Rate Limiter
- Orquestador de 3 Capas: cortocircuitos de Whitelist/Blacklist y tope de cuota VT por correo
- EC-IMAP-01: Bloqueo de IMAP Command Injection en UIDs y nombres de carpeta
- EC-IMAP-02 / EC-IMAP-03: Flujo integral de Cuarentena en vivo y manejo de desconexión abrupta
- EC-EXT-04: Parseo seguro de URLhaus y rechazo de orígenes inseguros HTTP
"""

import ast
from collections import namedtuple
from pathlib import Path
import httpx
import pytest

from app.core.config import build_config_from_mapping
from app.core.types import ExtractedLink, ParsedEmail, VtLayerResult, make_secret
from app.db.database import get_dashboard_stats, init_database, open_db_connection
from app.services.detection.engine import evaluate_parsed_email, evaluate_single_link
from app.services.detection.vt_layer import (
    encode_vt_url_id,
    make_rate_limiter,
    parse_vt_json_payload,
    query_virustotal_url,
)
from app.services.imap_service import (
    poll_inbox_once,
    validate_imap_folder_name,
    validate_imap_uid,
)
from scripts.update_feeds import download_feed_bounded, parse_urlhaus_csv, sync_urlhaus_feed

FakeImapClient = namedtuple(
    "FakeImapClient", ["select", "uid", "list", "create", "expunge", "logout"]
)


def test_zero_oop_classes_in_stage3_modules() -> None:
    """Garantiza por AST que ningún módulo de la Etapa 3 ni el script usa `class`."""
    files_to_audit = (
        Path("app/services/detection/vt_layer.py"),
        Path("app/services/detection/engine.py"),
        Path("app/services/imap_service.py"),
        Path("scripts/update_feeds.py"),
    )
    for file_path in files_to_audit:
        tree = ast.parse(file_path.read_text(encoding="utf-8"))
        class_defs = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        assert class_defs == [], f"Clase POO detectada en {file_path}"


def test_ec_ext_01_02_03_virustotal_resilience_and_rate_limiter() -> None:
    """Prueba codificación Base64 sin padding, rate limiter por clausura y errores 429/Timeout/JSON."""
    assert "=" not in encode_vt_url_id("https://evil-aduanas.com/pago?guia=123")

    # Rate limiter funcional con reloj simulado (cero esperas reales en el test)
    fake_time = [100.0]
    slept: list[float] = []

    def _clock() -> float:
        return fake_time[0]

    def _sleep(sec: float) -> None:
        slept.append(round(sec, 2))
        fake_time[0] += sec

    limiter = make_rate_limiter(16.0, clock_fn=_clock, sleep_fn=_sleep)
    limiter()  # Primera llamada no duerme
    fake_time[0] += 6.0  # Pasaron solo 6s
    limiter()  # Debe dormir exactamente 10s
    assert slept == [10.0]

    api_secret = make_secret("fake_vt_key")

    # EC-EXT-01: HTTP 429 Too Many Requests -> degradación limpia sin excepción
    res_429 = query_virustotal_url(
        "https://unknown-site.org/doc",
        api_secret,
        http_get_fn=lambda url, headers, timeout: httpx.Response(429),
    )
    assert res_429 == VtLayerResult(0, 0, error="vt_rate_limited_429")

    # EC-EXT-02: Timeout de red -> degradación limpia
    def _raise_timeout(url: str, headers: dict, timeout: float) -> httpx.Response:
        raise httpx.TimeoutException("Read timed out")

    res_timeout = query_virustotal_url(
        "https://unknown-site.org/doc", api_secret, http_get_fn=_raise_timeout
    )
    assert res_timeout == VtLayerResult(0, 0, error="vt_timeout")

    # EC-EXT-03: JSON inesperado o truncado
    assert parse_vt_json_payload({"unexpected": 123}).error == "missing_vt_data_field"

    # Respuesta 200 válida con 3 motores maliciosos
    valid_json = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1}}}}
    res_ok = query_virustotal_url(
        "https://phishing-cargo.net/login",
        api_secret,
        http_get_fn=lambda url, headers, timeout: httpx.Response(200, json=valid_json),
    )
    assert res_ok.malicious_count == 3
    assert res_ok.suspicious_count == 1
    assert res_ok.error == ""


def test_engine_short_circuits_and_vt_quota_cap() -> None:
    """Comprueba cortocircuitos de Capa 1 y límite máximo de llamadas a VirusTotal por correo."""
    cfg = build_config_from_mapping({})
    whitelist = frozenset({"maersk.com", "seniat.gob.ve"})
    vt_calls: list[str] = []

    def _fake_vt(url: str) -> VtLayerResult:
        vt_calls.append(url)
        return VtLayerResult(malicious_count=2, suspicious_count=0, error="")

    # 1. Dominio en Whitelist legítimo -> 0 llamadas a VT y score 0
    safe_verdict = evaluate_single_link(
        link=ExtractedLink("https://tracking.maersk.com/123", "Rastrear", "tracking.maersk.com"),
        email_subject="Estado de carga",
        email_body="Su contenedor está en tránsito.",
        config=cfg,
        whitelisted_domains=whitelist,
        is_blacklisted_fn=lambda u, d: False,
        vt_query_fn=_fake_vt,
    )
    assert safe_verdict.final_score == 0
    assert safe_verdict.verdict == "SAFE"
    assert len(vt_calls) == 0

    # 2. Enlace en Whitelist PERO con texto engañoso HTML (`seniat.gob.ve` visible -> `maersk.com` o viceversa)
    # Verifica que un correo con 6 enlaces desconocidos solo haga máximo 3 consultas a VT
    links = tuple(
        ExtractedLink(f"https://unknown-exporter-{i}.org/file", "Archivo", f"unknown-exporter-{i}.org")
        for i in range(6)
    )
    parsed = ParsedEmail("<id-quota@test>", "info@test.com", "Documentos", "Adjunto", links)
    max_score, status, should_quarantine, verdicts = evaluate_parsed_email(
        parsed_email=parsed,
        config=cfg,
        whitelisted_domains=whitelist,
        is_blacklisted_fn=lambda u, d: False,
        vt_query_fn=_fake_vt,
        max_vt_queries_per_email=3,
    )
    assert len(vt_calls) == 3
    assert max_score == 70  # 2 motores maliciosos * 35 pts = 70 >= 60
    assert status == "QUARANTINED"
    assert should_quarantine is True
    assert len(verdicts) == 6


def test_ec_imap_01_injection_and_ec_imap_02_03_live_quarantine_flow(tmp_path: Path) -> None:
    """Valida bloqueo de IMAP Injection y simula un ciclo completo de detección y cuarentena."""
    # EC-IMAP-01: Rechazo de inyecciones CRLF y comandos en UID y carpetas
    with pytest.raises(ValueError):
        validate_imap_uid("105\r\nA02 DELETE INBOX")
    with pytest.raises(ValueError):
        validate_imap_uid("1:*")
    with pytest.raises(ValueError):
        validate_imap_folder_name('Cuarentena"\r\nDELETE INBOX')

    assert validate_imap_uid(b"42") == "42"
    assert validate_imap_folder_name("Cuarentena") == "Cuarentena"

    # EC-IMAP-02: Simulación funcional completa de buzón con 1 correo limpio y 1 correo phishing
    db_file = str(tmp_path / "imap_flow.db")
    init_database(db_file)
    cfg = build_config_from_mapping(
        {
            "DATABASE_URL": f"sqlite:///{db_file}",
            "EMAIL_USER": "operaciones@importadora-chacao.com",
            "EMAIL_PASSWORD": "app_password_123",
            "QUARANTINE_FOLDER": "Cuarentena",
        }
    )

    clean_mime = (
        b"Message-ID: <clean-101@maersk.com>\r\n"
        b"From: notificaciones@maersk.com\r\n"
        b"Subject: Confirmacion de embarque\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Rastree su contenedor en https://www.maersk.com/tracking/9988"
    )
    phish_mime = (
        b"Message-ID: <phish-102@evil.ru>\r\n"
        b"From: soporte@aduana-alerta.com\r\n"
        b"Subject: URGENTE: Guia retenida y pago de aranceles SENIAT\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b'<html><body>Pague ya en <a href="http://seniat.gob.ve@dhl-pagos-ve.com:8443/login">'
        b"https://seniat.gob.ve/pagos</a></body></html>"
    )

    imap_actions: list[tuple[str, ...]] = []
    messages_by_uid = {"101": clean_mime, "102": phish_mime}

    def _fake_uid(cmd: str, *args: str) -> tuple[str, list]:
        cmd_upper = cmd.upper()
        if cmd_upper == "SEARCH":
            return ("OK", [b"101 102"])
        if cmd_upper == "FETCH":
            target_uid = args[0]
            return ("OK", [(b"RFC822", messages_by_uid[target_uid])])
        if cmd_upper == "COPY":
            imap_actions.append(("COPY", args[0], args[1]))
            return ("OK", [b"Copied"])
        if cmd_upper == "STORE":
            imap_actions.append(("STORE", args[0], args[2]))
            return ("OK", [b"Marked deleted"])
        return ("BAD", [])

    fake_client = FakeImapClient(
        select=lambda box: ("OK", [b"2"]),
        uid=_fake_uid,
        list=lambda: ("OK", [b'(\\HasNoChildren) "/" "INBOX"']),
        create=lambda folder: imap_actions.append(("CREATE", folder)) or ("OK", [b"Created"]),
        expunge=lambda: imap_actions.append(("EXPUNGE",)) or ("OK", []),
        logout=lambda: imap_actions.append(("LOGOUT",)) or ("BYE", []),
    )

    analyzed, quarantined = poll_inbox_once(
        config=cfg,
        vt_query_fn=None,
        imap_factory_fn=lambda _c: fake_client,
    )

    assert analyzed == 2
    assert quarantined == 1
    # Verificar que solo el UID 102 (phishing) fue creado/copiado/expurgado hacia Cuarentena
    assert ("CREATE", "Cuarentena") in imap_actions
    assert ("COPY", "102", "Cuarentena") in imap_actions
    assert ("EXPUNGE",) in imap_actions
    assert ("LOGOUT",) in imap_actions
    assert ("COPY", "101", "Cuarentena") not in imap_actions

    with open_db_connection(db_file) as conn:
        stats = get_dashboard_stats(conn)
        assert stats.total_emails == 2
        assert stats.clean_emails == 1
        assert stats.quarantined_emails == 1

    # EC-IMAP-03: Caída abrupta de red no debe tumbar el proceso
    def _broken_factory(_c: object) -> object:
        raise OSError("Network unreachable")

    assert poll_inbox_once(config=cfg, imap_factory_fn=_broken_factory) == (0, 0)


def test_ec_ext_04_urlhaus_feed_parser_and_https_enforcement(tmp_path: Path) -> None:
    """Comprueba rechazo de feeds sin HTTPS y sincronización transaccional desde CSV URLhaus."""
    with pytest.raises(ValueError):
        download_feed_bounded("http://insecure-feed.example.com/list.csv")

    sample_csv = (
        "# URLhaus Kommentar\n"
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        '1001,"2026-11-24","http://malware-naviera.ru/factura.exe","online","2026-11-24","malware_download","exe","https://urlhaus","abuse"\n'
        '1002,"2026-11-24","javascript:alert(1)","online","2026-11-24","xss","js","https://urlhaus","abuse"\n'
    )
    parsed = parse_urlhaus_csv(sample_csv)
    assert len(parsed) == 1
    assert parsed[0][1] == "malware-naviera.ru"

    db_file = str(tmp_path / "feeds.db")
    inserted = sync_urlhaus_feed(
        db_path=db_file,
        feed_url="https://urlhaus.abuse.ch/downloads/csv_online/",
        downloader_fn=lambda _url: sample_csv,
    )
    assert inserted == 1
