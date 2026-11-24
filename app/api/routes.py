"""
Endpoints REST funcionales del Dashboard.
Implementa validación estricta de entradas (OWASP ASVS V5), paginación acotada
y neutralización visual (defanging) para el analizador manual y auditoría.
"""

from typing import Any, Callable
from fastapi import APIRouter, Body, HTTPException, Query

from app.core.types import AppConfig, ExtractedLink, VtLayerResult
from app.db.database import (
    fetch_whitelisted_domains,
    get_dashboard_stats,
    is_url_or_domain_blacklisted,
    list_recent_emails,
    open_db_connection,
    save_url_verdicts,
)
from app.services.detection.engine import evaluate_single_link
from app.services.parser_service import extract_domain_safe


def validate_manual_analyze_payload(
    payload: Any, max_url_length: int = 2048
) -> tuple[str, str, str]:
    """
    Función pura de validación de entrada para `POST /api/v1/analyze`.
    Rechaza tipos inválidos, URLs vacías o cadenas que excedan los límites anti-DoS.
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="El cuerpo de la petición debe ser un objeto JSON.")

    raw_url = payload.get("url")
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise HTTPException(status_code=422, detail="El campo 'url' es obligatorio y debe ser texto.")

    clean_url = raw_url.strip()
    if len(clean_url) > max_url_length:
        raise HTTPException(
            status_code=422,
            detail=f"La URL excede el límite máximo permitido de {max_url_length} caracteres.",
        )

    raw_subject = payload.get("subject", "")
    raw_body = payload.get("body", "")
    if not isinstance(raw_subject, str) or not isinstance(raw_body, str):
        raise HTTPException(status_code=422, detail="Los campos 'subject' y 'body' deben ser texto.")

    return (clean_url, raw_subject.strip()[:500], raw_body.strip()[:5000])


def create_api_router(
    config: AppConfig,
    vt_query_fn: Callable[[str], VtLayerResult] | None = None,
) -> APIRouter:
    """
    Fábrica funcional de rutas API v1 con inyección de configuración y cliente VirusTotal.
    """
    router = APIRouter(prefix="/api/v1", tags=["dashboard"])

    @router.get("/health")
    def health_check() -> dict[str, str]:
        return {"status": "ok", "service": config.project_name, "version": config.version}

    @router.get("/stats")
    def read_stats() -> dict[str, int]:
        with open_db_connection(config.database_path) as conn:
            stats = get_dashboard_stats(conn)
        return stats._asdict()

    @router.get("/emails")
    def read_recent_emails(
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, Any]:
        with open_db_connection(config.database_path) as conn:
            records = list_recent_emails(conn, limit=limit)
        return {
            "count": len(records),
            "items": [rec._asdict() for rec in records],
        }

    @router.get("/emails/{email_id}/urls")
    def read_email_urls(email_id: int) -> dict[str, Any]:
        if email_id < 1:
            raise HTTPException(status_code=422, detail="El identificador de correo debe ser positivo.")

        with open_db_connection(config.database_path) as conn:
            exists = conn.execute(
                "SELECT 1 FROM processed_emails WHERE id = ? LIMIT 1",
                (email_id,),
            ).fetchone()
            if exists is None:
                raise HTTPException(status_code=404, detail="Correo no encontrado.")

            rows = conn.execute(
                """
                SELECT id, original_url, defanged_url, visible_text, domain,
                       layer1_status, vt_malicious_count, vt_suspicious_count,
                       heuristic_score, heuristic_reasons, final_score, verdict, analyzed_at
                FROM analyzed_urls
                WHERE email_id = ?
                ORDER BY final_score DESC, id ASC
                """,
                (email_id,),
            ).fetchall()

        items = [
            {
                "id": int(r["id"]),
                "defanged_url": str(r["defanged_url"]),
                "visible_text": str(r["visible_text"] or ""),
                "domain": str(r["domain"]),
                "layer1_status": str(r["layer1_status"]),
                "vt_malicious_count": int(r["vt_malicious_count"]),
                "vt_suspicious_count": int(r["vt_suspicious_count"]),
                "heuristic_score": int(r["heuristic_score"]),
                "heuristic_reasons": [x for x in str(r["heuristic_reasons"]).split("|") if x],
                "final_score": int(r["final_score"]),
                "verdict": str(r["verdict"]),
                "analyzed_at": str(r["analyzed_at"]),
            }
            for r in rows
        ]
        return {"email_id": email_id, "count": len(items), "items": items}

    @router.post("/analyze")
    def analyze_manual_url(payload: Any = Body(...)) -> dict[str, Any]:
        clean_url, subject, body = validate_manual_analyze_payload(
            payload, max_url_length=config.max_url_length
        )
        domain = extract_domain_safe(clean_url, max_url_length=config.max_url_length)
        link = ExtractedLink(url=clean_url, visible_text="", domain=domain)

        with open_db_connection(config.database_path) as conn:
            whitelist = fetch_whitelisted_domains(conn)
            verdict = evaluate_single_link(
                link=link,
                email_subject=subject,
                email_body=body,
                config=config,
                whitelisted_domains=whitelist,
                is_blacklisted_fn=lambda u, d: is_url_or_domain_blacklisted(conn, u, d),
                vt_query_fn=vt_query_fn,
                allow_vt_lookup=vt_query_fn is not None,
            )
            save_url_verdicts(conn, (verdict,), email_id=None)

        return {
            "defanged_url": verdict.defanged_url,
            "domain": verdict.domain,
            "layer1_status": verdict.layer1_status,
            "vt_malicious_count": verdict.vt_malicious_count,
            "vt_suspicious_count": verdict.vt_suspicious_count,
            "heuristic_score": verdict.heuristic_score,
            "heuristic_reasons": list(verdict.heuristic_reasons),
            "final_score": verdict.final_score,
            "verdict": verdict.verdict,
        }

    return router
