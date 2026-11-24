"""
Capa 1 del Motor Híbrido (100% Funcional / Cero Clases):
Evaluación local contra Lista Negra (URLhaus/OpenPhish) y Lista Blanca corporativa.
Garantiza validación estricta de sufijos de dominio para impedir bypass (EC-URL-05).
"""

from typing import Callable
from app.core.types import LocalLayerResult
from app.services.parser_service import normalize_hostname_to_ascii


def is_domain_strictly_whitelisted(domain: str, whitelisted_domains: frozenset[str]) -> bool:
    """
    Función pura determinista que verifica si `domain` es exactamente un dominio confiable
    o un subdominio legítimo directo (precedido por punto `.`).
    Bloquea engaños como `maersk.com.evil.ru` o `fakemaersk.com` (EC-URL-05).
    """
    normalized = normalize_hostname_to_ascii(domain)
    if not normalized or normalized.endswith(".invalid"):
        return False

    if normalized in whitelisted_domains:
        return True

    for trusted in whitelisted_domains:
        clean_trusted = trusted.strip().lower().lstrip(".")
        if clean_trusted and normalized.endswith(f".{clean_trusted}"):
            return True

    return False


def evaluate_local_layer(
    url: str,
    domain: str,
    whitelisted_domains: frozenset[str],
    is_blacklisted_fn: Callable[[str, str], bool],
) -> LocalLayerResult:
    """
    Función de orden superior para la Capa 1:
    1. Consulta primero la lista negra local (`is_blacklisted_fn`) por principio de precaución.
    2. Si no es maliciosa conocida, verifica coincidencia estricta con `whitelisted_domains`.
    3. En caso contrario retorna `UNKNOWN` para continuar con las Capas 2 y 3.
    """
    clean_url = url.strip()
    clean_domain = normalize_hostname_to_ascii(domain)

    if is_blacklisted_fn(clean_url, clean_domain):
        return LocalLayerResult(status="BLACKLISTED", reason="local_threat_feed_match")

    if is_domain_strictly_whitelisted(clean_domain, whitelisted_domains):
        return LocalLayerResult(status="WHITELISTED", reason="trusted_corporate_domain")

    return LocalLayerResult(status="UNKNOWN", reason="not_in_local_cache")
