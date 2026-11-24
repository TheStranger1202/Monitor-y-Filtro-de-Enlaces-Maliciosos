"""
Capa 3 del Motor Híbrido (100% Funcional / Cero Clases):
Reglas heurísticas contextualizadas para compañías de importación y exportación en Chacao.
Detecta homógrafos IDN, typosquatting aduanero/naviero, IPs directas/privadas,
credenciales embebidas, discrepancia href vs texto visible y jerga de ingeniería social.
"""

import ipaddress
import re
from urllib.parse import urlsplit
from rapidfuzz.distance import Levenshtein

from app.core.security import has_dangerous_scheme
from app.core.types import ExtractedLink, HeuristicResult
from app.services.parser_service import normalize_hostname_to_ascii

# Soporta dominios simples (dhl.com), subdominios (track.maersk.com) y ccTLDs compuestos (seniat.gob.ve)
_LOOKS_LIKE_DOMAIN_RE = re.compile(
    r"^(?:https?://)?((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::\d+)?(?:/.*)?$"
)


def classify_ip_host(domain: str) -> str | None:
    """
    Función pura que detecta si el host es una dirección IPv4/IPv6 (EC-URL-03)
    y distingue si apunta a rangos privados/loopback/reservados (EC-URL-04).
    Retorna: `'private_or_loopback_ip'` | `'direct_public_ip'` | `None`.
    """
    if not domain:
        return None
    candidate = domain.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        return None

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
        return "private_or_loopback_ip"
    return "direct_public_ip"


def has_embedded_credentials(url: str) -> bool:
    """Detecta trucos de suplantación `https://seniat.gob.ve@evil.com/pago` (EC-URL-02)."""
    try:
        parsed = urlsplit(url.strip())
    except ValueError:
        return False
    return bool(parsed.username or parsed.password or "@" in parsed.netloc)


def has_non_standard_port(url: str) -> bool:
    """Detecta puertos inusuales distintos de 80 y 443 (EC-URL-07)."""
    try:
        parsed = urlsplit(url.strip())
        port = parsed.port
    except ValueError:
        return True
    return port is not None and port not in (80, 443)


def has_punycode_homograph(domain: str) -> bool:
    """Detecta etiquetas Punycode (`xn--`) típicas de ataques IDN homográficos (EC-URL-01)."""
    if not domain:
        return False
    return any(label.startswith("xn--") for label in domain.lower().split("."))


def detect_logistics_typosquatting(
    domain: str, protected_domains: tuple[str, ...]
) -> str | None:
    """
    Función pura que detecta suplantación contra navieras, couriers y entes aduaneros:
    1. Si es exactamente el dominio legítimo o un subdominio real suyo -> Seguro (`None`).
    2. Distancia de edición Levenshtein entre 1 y 2 en dominio completo o etiqueta base (`dhl.com` vs `dh1.com`).
    3. Brand-Combo-Squatting: incluye la marca protegida con guiones (`dhl-aduanas-ve.com`, `seniat-pagos.net`).
    """
    clean_domain = normalize_hostname_to_ascii(domain)
    if not clean_domain or clean_domain.endswith(".invalid"):
        return None

    for protected in protected_domains:
        prot = protected.lower().strip()
        if clean_domain == prot or clean_domain.endswith(f".{prot}"):
            return None

    domain_parts = clean_domain.split(".")
    registrable_candidate = (
        ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else clean_domain
    )
    candidate_brand_label = domain_parts[-2] if len(domain_parts) >= 2 else domain_parts[0]

    for protected in protected_domains:
        prot = protected.lower().strip()
        prot_brand = prot.split(".")[0]

        dist_full = Levenshtein.distance(registrable_candidate, prot)
        if 1 <= dist_full <= 2:
            return f"typosquatting_near_{prot}"

        if len(prot_brand) >= 5:
            dist_brand = Levenshtein.distance(candidate_brand_label, prot_brand)
            if dist_brand == 1:
                return f"typosquatting_brand_{prot_brand}"

        if len(prot_brand) >= 3 and (
            f"{prot_brand}-" in clean_domain or f"-{prot_brand}" in clean_domain
        ):
            return f"brand_impersonation_{prot_brand}"

    return None


def has_anchor_href_mismatch(visible_text: str, actual_domain: str) -> bool:
    """
    Detecta discrepancia visual en HTML (`<a href="https://evil.ru">https://seniat.gob.ve/aranceles</a>`)
    donde el texto visible finge ser un dominio distinto al real (EC-URL-06).
    """
    if not visible_text or not actual_domain:
        return False
    compact = visible_text.strip()
    if " " in compact:
        return False

    match = _LOOKS_LIKE_DOMAIN_RE.match(compact)
    if not match:
        return False

    claimed_domain = normalize_hostname_to_ascii(match.group(1))
    real_domain = normalize_hostname_to_ascii(actual_domain)
    if not claimed_domain or not real_domain:
        return False

    if real_domain == claimed_domain or real_domain.endswith(f".{claimed_domain}"):
        return False
    if claimed_domain.endswith(f".{real_domain}"):
        return False

    return True


def is_url_shortener(domain: str, shorteners: tuple[str, ...]) -> bool:
    """Verifica si el enlace emplea un acortador de URLs que oculta el destino real."""
    clean = normalize_hostname_to_ascii(domain)
    return any(clean == s or clean.endswith(f".{s}") for s in shorteners)


def count_customs_keywords(subject: str, body_text: str, keywords: tuple[str, ...]) -> int:
    """Cuenta cuántas frases de ingeniería social aduanera aparecen en asunto o cuerpo."""
    haystack = f"{subject} {body_text}".lower()
    return sum(1 for kw in keywords if kw.lower() in haystack)


def evaluate_heuristic_layer(
    link: ExtractedLink,
    email_subject: str,
    email_body: str,
    protected_domains: tuple[str, ...],
    customs_keywords: tuple[str, ...],
    url_shorteners: tuple[str, ...],
    max_url_length: int = 2048,
) -> HeuristicResult:
    """
    Función pura principal de la Capa 3: evalúa todas las señales estructurales y de
    comercio exterior devolviendo un `HeuristicResult(score, reasons)` acotado en [0, 100].
    """
    score = 0
    reasons: list[str] = []
    raw_url = link.url.strip()

    if len(raw_url) >= max_url_length:
        score += 25
        reasons.append("excessive_url_length")

    if has_dangerous_scheme(raw_url):
        return HeuristicResult(score=100, reasons=("dangerous_executable_scheme",))

    if has_embedded_credentials(raw_url):
        score += 65
        reasons.append("embedded_url_credentials")

    ip_kind = classify_ip_host(link.domain)
    if ip_kind == "private_or_loopback_ip":
        score += 75
        reasons.append("private_or_loopback_ip_host")
    elif ip_kind == "direct_public_ip":
        score += 45
        reasons.append("direct_ip_address_host")

    if has_punycode_homograph(link.domain):
        score += 45
        reasons.append("idn_punycode_homograph")

    typo_match = detect_logistics_typosquatting(link.domain, protected_domains)
    if typo_match:
        score += 55
        reasons.append(typo_match)

    if has_anchor_href_mismatch(link.visible_text, link.domain):
        score += 50
        reasons.append("anchor_text_domain_mismatch")

    if has_non_standard_port(raw_url):
        score += 25
        reasons.append("non_standard_port")

    if is_url_shortener(link.domain, url_shorteners):
        score += 20
        reasons.append("url_shortener_used")

    kw_hits = count_customs_keywords(email_subject, email_body, customs_keywords)
    if kw_hits >= 2:
        score += 25
        reasons.append(f"multiple_customs_lure_keywords({kw_hits})")
    elif kw_hits == 1:
        score += 15
        reasons.append("customs_lure_keyword")

    bounded_score = min(100, max(0, score))
    return HeuristicResult(score=bounded_score, reasons=tuple(reasons))
