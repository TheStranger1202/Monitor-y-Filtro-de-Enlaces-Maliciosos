"""
Suite de pruebas funcionales y de seguridad del Frontend (Etapa 4B / OWASP).
Valida:
- Renderizado correcto de `GET /` del Dashboard
- Carga de archivos estáticos `/static/styles.css` y `/static/app.js`
- Endurecimiento de Content-Security-Policy (sin `unsafe-inline` en script-src ni style-src)
- Prohibición de `innerHTML` y clases POO en `app/frontend/static/app.js` (anti-Stored XSS EC-XSS-01)
"""

from pathlib import Path
from fastapi.testclient import TestClient

from app.core.config import build_config_from_mapping
from app.main import create_app


def test_frontend_routes_and_strict_csp(tmp_path: Path) -> None:
    """Verifica que GET / y /static/* respondan 200 OK con cabecera CSP sin unsafe-inline."""
    db_file = str(tmp_path / "frontend_test.db")
    cfg = build_config_from_mapping({"DATABASE_URL": f"sqlite:///{db_file}"})
    test_app = create_app(config=cfg, enable_imap_worker=False)

    with TestClient(test_app) as client:
        home = client.get("/")
        assert home.status_code == 200
        assert "PHISHGUARD" in home.text

        csp = home.headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp
        assert "style-src 'self'" in csp
        assert "unsafe-inline" not in csp

        css_resp = client.get("/static/styles.css")
        assert css_resp.status_code == 200
        assert "--bg-abyss" in css_resp.text

        js_resp = client.get("/static/app.js")
        assert js_resp.status_code == 200
        assert "refreshTelemetry" in js_resp.text


def test_ec_xss_01_frontend_js_has_no_innerhtml_or_oop_classes() -> None:
    """Audita app.js para garantizar ausencia de innerHTML (XSS) y ausencia de clases POO."""
    js_code = Path("app/frontend/static/app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js_code
    assert "insertAdjacentHTML" not in js_code
    assert "outerHTML" not in js_code
    assert "\nclass " not in js_code
    assert "textContent" in js_code
