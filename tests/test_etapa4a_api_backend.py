"""
Suite de pruebas funcionales y de seguridad HTTP (OWASP) para la Etapa 4A (API Backend).
Valida:
- Auditoría AST en `app/api/routes.py` y `app/main.py`
- Presencia obligatoria de cabeceras OWASP (CSP, X-Frame-Options, nosniff, Referrer-Policy)
- Endpoints de estadísticas, listado acotado de correos y detalle de URLs
- Analizador manual (`POST /api/v1/analyze`) frente a phishing aduanero, XSS (`EC-XSS-01`, `EC-XSS-02`)
  y límites anti-DoS (> 2048 caracteres)
"""

import ast
from pathlib import Path
from fastapi.testclient import TestClient

from app.core.config import build_config_from_mapping
from app.core.security import defang_url
from app.core.types import UrlVerdict
from app.db.database import init_database, open_db_connection, save_email_analysis
from app.main import create_app


def test_zero_oop_classes_in_stage4a_modules() -> None:
    """Garantiza por AST que ni routes.py ni main.py definen clases POO."""
    for file_path in (Path("app/api/routes.py"), Path("app/main.py")):
        tree = ast.parse(file_path.read_text(encoding="utf-8"))
        class_defs = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        assert class_defs == [], f"Clase POO detectada en {file_path}"


def test_owasp_headers_and_health_endpoint(tmp_path: Path) -> None:
    """Verifica que las cabeceras de seguridad OWASP estén presentes en las respuestas HTTP."""
    db_file = str(tmp_path / "api_health.db")
    cfg = build_config_from_mapping({"DATABASE_URL": f"sqlite:///{db_file}"})
    test_app = create_app(config=cfg, enable_imap_worker=False)

    with TestClient(test_app) as client:
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'self'" in resp.headers["Content-Security-Policy"]


def test_manual_analyzer_customs_phishing_and_edge_cases(tmp_path: Path) -> None:
    """Somete `POST /api/v1/analyze` a phishing aduanero, XSS (EC-XSS-02) y URL gigante."""
    db_file = str(tmp_path / "api_analyze.db")
    cfg = build_config_from_mapping({"DATABASE_URL": f"sqlite:///{db_file}"})
    test_app = create_app(config=cfg, enable_imap_worker=False)

    with TestClient(test_app) as client:
        # 1. URL legítima en Lista Blanca
        res_safe = client.post(
            "/api/v1/analyze",
            json={"url": "https://www.maersk.com/tracking", "subject": "Embarque"},
        )
        assert res_safe.status_code == 200
        data_safe = res_safe.json()
        assert data_safe["verdict"] == "SAFE"
        assert data_safe["final_score"] == 0

        # 2. Phishing aduanero Chacao
        res_phish = client.post(
            "/api/v1/analyze",
            json={
                "url": "http://seniat.gob.ve@dhl-aranceles-ve.com:8443/pago",
                "subject": "Guía retenida: pago de aranceles urgente",
            },
        )
        assert res_phish.status_code == 200
        data_phish = res_phish.json()
        assert data_phish["verdict"] == "MALICIOUS"
        assert data_phish["final_score"] >= 60
        assert "[.]" in data_phish["defanged_url"]

        # 3. EC-XSS-02: Esquema ejecutable javascript:
        res_xss = client.post(
            "/api/v1/analyze",
            json={"url": "javascript:alert(document.cookie)"},
        )
        assert res_xss.status_code == 200
        data_xss = res_xss.json()
        assert data_xss["verdict"] == "MALICIOUS"
        assert data_xss["final_score"] == 100
        assert data_xss["defanged_url"].startswith("blocked-javascript:")

        # 4. Anti-DoS: URL mayor a 2048 caracteres -> rechazada con 422
        res_huge = client.post(
            "/api/v1/analyze",
            json={"url": "https://evil.com/" + ("x" * 2100)},
        )
        assert res_huge.status_code == 422

        # 5. Cuerpo vacío o sin campo url -> rechazado con 422
        res_empty = client.post("/api/v1/analyze", json={"url": "   "})
        assert res_empty.status_code == 422


def test_stats_emails_and_url_details_endpoints(tmp_path: Path) -> None:
    """Verifica endpoints de métricas, listado paginado y detalle de enlaces por correo."""
    db_file = str(tmp_path / "api_stats.db")
    init_database(db_file)

    mal_url = "https://dhl-pagos-chacao.net/factura"
    verdict = UrlVerdict(
        original_url=mal_url,
        defanged_url=defang_url(mal_url),
        visible_text="Pagar factura",
        domain="dhl-pagos-chacao.net",
        layer1_status="UNKNOWN",
        vt_malicious_count=2,
        vt_suspicious_count=0,
        heuristic_score=70,
        heuristic_reasons=("brand_impersonation_dhl", "customs_lure_keyword"),
        final_score=100,
        verdict="MALICIOUS",
    )

    with open_db_connection(db_file) as conn:
        email_id = save_email_analysis(
            conn=conn,
            message_id="<api-test-01@evil.com>",
            sender="alertas@dhl-pagos-chacao.net",
            subject="<script>alert('xss')</script> Guía retenida",
            max_risk_score=100,
            status="QUARANTINED",
            quarantined=True,
            verdicts=(verdict,),
        )

    cfg = build_config_from_mapping({"DATABASE_URL": f"sqlite:///{db_file}"})
    test_app = create_app(config=cfg, enable_imap_worker=False)

    with TestClient(test_app) as client:
        stats = client.get("/api/v1/stats").json()
        assert stats["total_emails"] == 1
        assert stats["quarantined_emails"] == 1
        assert stats["total_malicious_urls"] == 1

        emails_resp = client.get("/api/v1/emails?limit=10")
        assert emails_resp.status_code == 200
        assert emails_resp.json()["count"] == 1

        # Paginación fuera de rango (>200) rechazada por FastAPI Query
        assert client.get("/api/v1/emails?limit=500").status_code == 422

        urls_resp = client.get(f"/api/v1/emails/{email_id}/urls")
        assert urls_resp.status_code == 200
        urls_data = urls_resp.json()
        assert urls_data["count"] == 1
        assert urls_data["items"][0]["defanged_url"] == "hxxps://dhl-pagos-chacao[.]net/factura"

        # Correo inexistente -> 404
        assert client.get("/api/v1/emails/9999/urls").status_code == 404
