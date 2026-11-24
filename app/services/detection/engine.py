"""
Orquestador Funcional del Motor de Detección Híbrido en 3 Capas (Cero Clases POO).
Combina Capa 1 (SQLite/Whitelist), Capa 2 (VirusTotal v3) y Capa 3 (Heurística Aduanera).
"""

from typing import Callable
from app.core.security import defang_url
from app.core.types import (
    AppConfig,
    ExtractedLink,
    ParsedEmail,
    UrlVerdict,
    VtLayerResult,
)
from app.services.detection.heuristic_layer import (
    evaluate_heuristic_layer,
    has_anchor_href_mismatch,
    has_embedded_credentials,
)
from app.services.detection.local_layer import evaluate_local_layer


def compute_vt_score(malicious_count: int, suspicious_count: int) -> int:
    """
    Fórmula matemática pura para la Capa 2:
    Cada motor 'malicious' aporta 35 pts (con 2 motores alcanza 70 >= umbral de cuarentena 60).
    Cada motor 'suspicious' aporta 15 pts.
    """
    raw = (max(0, malicious_count) * 35) + (max(0, suspicious_count) * 15)
    return min(100, raw)


def classify_verdict_label(score: int, config: AppConfig) -> str:
    """Traduce un puntaje numérico [0, 100] en una etiqueta de veredicto inmutable."""
    if score >= config.risk_threshold_quarantine:
        return "MALICIOUS"
    if score >= config.risk_threshold_suspicious:
        return "SUSPICIOUS"
    return "SAFE"


def classify_email_status(max_score: int, config: AppConfig) -> tuple[str, bool]:
    """
    Determina el estado global del correo (`CLEAN` | `SUSPICIOUS` | `QUARANTINED`)
    y el booleano de cuarentena a partir del enlace de mayor riesgo.
    """
    if max_score >= config.risk_threshold_quarantine:
        return ("QUARANTINED", True)
    if max_score >= config.risk_threshold_suspicious:
        return ("SUSPICIOUS", False)
    return ("CLEAN", False)


def evaluate_single_link(
    link: ExtractedLink,
    email_subject: str,
    email_body: str,
    config: AppConfig,
    whitelisted_domains: frozenset[str],
    is_blacklisted_fn: Callable[[str, str], bool],
    vt_query_fn: Callable[[str], VtLayerResult] | None = None,
    allow_vt_lookup: bool = True,
) -> UrlVerdict:
    """
    Función de orden superior que evalúa un enlace a través de las 3 capas:
    1. Capa 1: Si está en Blacklist -> 100 inmediato (ahorra API).
    2. Capa 1: Si está en Whitelist y el HTML no miente (sin mismatch ni user@host) -> 0 inmediato.
    3. Capa 3: Evalúa heurística contextual aduanera.
    4. Capa 2: Consulta VirusTotal si está habilitado y aún no alcanzó el tope de 100 pts.
    """
    safe_defanged = defang_url(link.url)
    local_res = evaluate_local_layer(
        url=link.url,
        domain=link.domain,
        whitelisted_domains=whitelisted_domains,
        is_blacklisted_fn=is_blacklisted_fn,
    )

    if local_res.status == "BLACKLISTED":
        return UrlVerdict(
            original_url=link.url,
            defanged_url=safe_defanged,
            visible_text=link.visible_text,
            domain=link.domain,
            layer1_status="BLACKLISTED",
            vt_malicious_count=0,
            vt_suspicious_count=0,
            heuristic_score=100,
            heuristic_reasons=(local_res.reason,),
            final_score=100,
            verdict="MALICIOUS",
        )

    # Verificar que un enlace hacia un dominio en lista blanca no sea parte de un engaño visual
    visual_spoof = has_anchor_href_mismatch(link.visible_text, link.domain)
    cred_spoof = has_embedded_credentials(link.url)

    if local_res.status == "WHITELISTED" and not visual_spoof and not cred_spoof:
        return UrlVerdict(
            original_url=link.url,
            defanged_url=safe_defanged,
            visible_text=link.visible_text,
            domain=link.domain,
            layer1_status="WHITELISTED",
            vt_malicious_count=0,
            vt_suspicious_count=0,
            heuristic_score=0,
            heuristic_reasons=(),
            final_score=0,
            verdict="SAFE",
        )

    heur_res = evaluate_heuristic_layer(
        link=link,
        email_subject=email_subject,
        email_body=email_body,
        protected_domains=config.protected_logistics_domains,
        customs_keywords=config.customs_phishing_keywords,
        url_shorteners=config.url_shorteners,
        max_url_length=config.max_url_length,
    )

    vt_res = VtLayerResult(0, 0, error="not_queried")
    if allow_vt_lookup and vt_query_fn is not None and heur_res.score < 100:
        vt_res = vt_query_fn(link.url)

    vt_points = compute_vt_score(vt_res.malicious_count, vt_res.suspicious_count)
    final_score = min(100, heur_res.score + vt_points)

    reasons = list(heur_res.reasons)
    if vt_points > 0:
        reasons.append(f"virustotal_detections(m={vt_res.malicious_count},s={vt_res.suspicious_count})")
    elif vt_res.error and vt_res.error not in ("not_queried", "vt_url_not_found", "vt_api_key_not_configured"):
        reasons.append(f"vt_degraded({vt_res.error})")

    verdict_label = classify_verdict_label(final_score, config)

    return UrlVerdict(
        original_url=link.url,
        defanged_url=safe_defanged,
        visible_text=link.visible_text,
        domain=link.domain,
        layer1_status=local_res.status,
        vt_malicious_count=vt_res.malicious_count,
        vt_suspicious_count=vt_res.suspicious_count,
        heuristic_score=heur_res.score,
        heuristic_reasons=tuple(reasons),
        final_score=final_score,
        verdict=verdict_label,
    )


def evaluate_parsed_email(
    parsed_email: ParsedEmail,
    config: AppConfig,
    whitelisted_domains: frozenset[str],
    is_blacklisted_fn: Callable[[str, str], bool],
    vt_query_fn: Callable[[str], VtLayerResult] | None = None,
    max_vt_queries_per_email: int = 4,
) -> tuple[int, str, bool, tuple[UrlVerdict, ...]]:
    """
    Evalúa todos los enlaces extraídos de un correo respetando un tope máximo
    de consultas externas a VirusTotal por mensaje (anti-agotamiento de cuota).
    Retorna `(max_risk_score, email_status, should_quarantine, verdicts_tuple)`.
    """
    if not parsed_email.links:
        return (0, "CLEAN", False, ())

    verdicts: list[UrlVerdict] = []
    vt_calls_used = 0

    for link in parsed_email.links:
        can_use_vt = vt_query_fn is not None and vt_calls_used < max_vt_queries_per_email
        verdict = evaluate_single_link(
            link=link,
            email_subject=parsed_email.subject,
            email_body=parsed_email.plain_text,
            config=config,
            whitelisted_domains=whitelisted_domains,
            is_blacklisted_fn=is_blacklisted_fn,
            vt_query_fn=vt_query_fn,
            allow_vt_lookup=can_use_vt,
        )
        # Contabilizar llamada a VT solo si pasó por UNKNOWN en Capa 1 y no tuvo cortocircuito heurístico 100
        if can_use_vt and verdict.layer1_status == "UNKNOWN" and verdict.heuristic_score < 100:
            vt_calls_used += 1
        verdicts.append(verdict)

    max_score = max((v.final_score for v in verdicts), default=0)
    email_status, should_quarantine = classify_email_status(max_score, config)
    return (max_score, email_status, should_quarantine, tuple(verdicts))
