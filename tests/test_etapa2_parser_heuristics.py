"""
Suite de pruebas funcionales y de casos borde (OWASP + Catálogo EC) para la Etapa 2.
Cubre:
- Auditoría AST de cero clases POO en todos los módulos nuevos
- EC-URL-01: Homógrafos IDN / Punycode (cirílico)
- EC-URL-02: Credenciales embebidas (`https://seniat.gob.ve@evil.com`)
- EC-URL-03 / EC-URL-04: IPs públicas directas, IPv6 e IPs privadas/loopback
- EC-URL-05: Intento de bypass de Lista Blanca (`maersk.com.evil.ru`, `fakemaersk.com`)
- EC-URL-06: Discrepancia entre texto visible `<a>` y atributo `href` real
- EC-URL-07: Puertos no estándar (`:8443`)
- EC-URL-08: URL hiper-larga contra ReDoS (CWE-1333)
- EC-MIME-01..05: Sin Message-ID, charsets rotos, solo HTML, límite de bytes y deduplicación
"""

import ast
import time
from pathlib import Path

from app.core.config import DEFAULT_CUSTOMS_KEYWORDS, DEFAULT_PROTECTED_DOMAINS, DEFAULT_URL_SHORTENERS
from app.core.types import ExtractedLink
from app.services.detection.heuristic_layer import evaluate_heuristic_layer
from app.services.detection.local_layer import evaluate_local_layer, is_domain_strictly_whitelisted
from app.services.parser_service import extract_domain_safe, parse_raw_email


def test_zero_oop_classes_in_stage2_modules() -> None:
    """Garantiza por AST que ningún módulo de la Etapa 2 define clases POO."""
    files_to_audit = (
        Path("app/services/parser_service.py"),
        Path("app/services/detection/local_layer.py"),
        Path("app/services/detection/heuristic_layer.py"),
    )
    for file_path in files_to_audit:
        tree = ast.parse(file_path.read_text(encoding="utf-8"))
        class_defs = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        assert class_defs == [], f"Clase POO detectada en {file_path}"


def test_ec_url_05_strict_whitelist_blocks_subdomain_spoofing() -> None:
    """Comprueba que subdominios falsos jamás burlen la Lista Blanca (EC-URL-05)."""
    whitelist = frozenset({"maersk.com", "seniat.gob.ve", "dhl.com"})

    assert is_domain_strictly_whitelisted("maersk.com", whitelist) is True
    assert is_domain_strictly_whitelisted("tracking.maersk.com", whitelist) is True
    assert is_domain_strictly_whitelisted("portal.seniat.gob.ve", whitelist) is True

    # Intentos clásicos de evasión
    assert is_domain_strictly_whitelisted("maersk.com.evil.ru", whitelist) is False
    assert is_domain_strictly_whitelisted("fakemaersk.com", whitelist) is False
    assert is_domain_strictly_whitelisted("seniat.gob.ve-pagos.com", whitelist) is False

    # Blacklist local siempre prevalece
    res_black = evaluate_local_layer(
        url="http://evil.ru/bl",
        domain="evil.ru",
        whitelisted_domains=whitelist,
        is_blacklisted_fn=lambda u, d: d == "evil.ru",
    )
    assert res_black.status == "BLACKLISTED"


def test_ec_url_01_02_06_07_customs_phishing_heuristics() -> None:
    """Evalúa homógrafos cirílicos, credenciales `@`, mismatch HTML, puertos y typosquatting."""
    # EC-URL-01: 'mаersk.com' con letra 'а' cirílica (\u0430)
    homograph_url = "https://m\u0430ersk.com/containers"
    homograph_domain = extract_domain_safe(homograph_url)
    assert homograph_domain.startswith("xn--")
    res_idn = evaluate_heuristic_layer(
        ExtractedLink(homograph_url, "Rastreo Maersk", homograph_domain),
        email_subject="Liberación de contenedor urgente",
        email_body="Su manifiesto de carga presenta pago de aranceles pendiente.",
        protected_domains=DEFAULT_PROTECTED_DOMAINS,
        customs_keywords=DEFAULT_CUSTOMS_KEYWORDS,
        url_shorteners=DEFAULT_URL_SHORTENERS,
    )
    assert res_idn.score >= 60
    assert "idn_punycode_homograph" in res_idn.reasons

    # EC-URL-02: Credenciales embebidas fingiendo ser SENIAT + puerto anómalo (EC-URL-07)
    cred_url = "http://seniat.gob.ve@phishing-chacao.net:8443/aranceles"
    cred_domain = extract_domain_safe(cred_url)
    assert cred_domain == "phishing-chacao.net"
    res_cred = evaluate_heuristic_layer(
        ExtractedLink(cred_url, "https://seniat.gob.ve/aranceles", cred_domain),
        email_subject="SENIAT: Factura aduanera pendiente",
        email_body="Realice el pago urgente.",
        protected_domains=DEFAULT_PROTECTED_DOMAINS,
        customs_keywords=DEFAULT_CUSTOMS_KEYWORDS,
        url_shorteners=DEFAULT_URL_SHORTENERS,
    )
    assert res_cred.score == 100
    assert "embedded_url_credentials" in res_cred.reasons
    assert "anchor_text_domain_mismatch" in res_cred.reasons
    assert "non_standard_port" in res_cred.reasons

    # Typosquatting logístico (dh1.com / dhl-aduanas.com)
    typo_link = ExtractedLink("https://dhl-aduanas-ve.com/guia", "Ver guía", "dhl-aduanas-ve.com")
    res_typo = evaluate_heuristic_layer(
        typo_link,
        email_subject="Guía retenida en aduana",
        email_body="Adjuntamos bill of lading.",
        protected_domains=DEFAULT_PROTECTED_DOMAINS,
        customs_keywords=DEFAULT_CUSTOMS_KEYWORDS,
        url_shorteners=DEFAULT_URL_SHORTENERS,
    )
    assert res_typo.score >= 70
    assert any("brand_impersonation_dhl" in r for r in res_typo.reasons)


def test_ec_url_03_04_ip_hosts_and_xss_schemes() -> None:
    """Valida detección de IPs privadas/loopback (anti-SSRF) y esquemas javascript:."""
    loopback_link = ExtractedLink("http://127.0.0.1/admin", "Panel", "127.0.0.1")
    res_loop = evaluate_heuristic_layer(
        loopback_link, "", "", DEFAULT_PROTECTED_DOMAINS, DEFAULT_CUSTOMS_KEYWORDS, DEFAULT_URL_SHORTENERS
    )
    assert res_loop.score >= 75
    assert "private_or_loopback_ip_host" in res_loop.reasons

    ipv6_url = "http://[2001:db8::1]/login"
    ipv6_domain = extract_domain_safe(ipv6_url)
    res_ipv6 = evaluate_heuristic_layer(
        ExtractedLink(ipv6_url, "Login", ipv6_domain),
        "",
        "",
        DEFAULT_PROTECTED_DOMAINS,
        DEFAULT_CUSTOMS_KEYWORDS,
        DEFAULT_URL_SHORTENERS,
    )
    assert res_ipv6.score >= 45

    xss_link = ExtractedLink("javascript:alert(1)", "Click", "dangerous-scheme.invalid")
    res_xss = evaluate_heuristic_layer(
        xss_link, "", "", DEFAULT_PROTECTED_DOMAINS, DEFAULT_CUSTOMS_KEYWORDS, DEFAULT_URL_SHORTENERS
    )
    assert res_xss.score == 100
    assert "dangerous_executable_scheme" in res_xss.reasons


def test_ec_url_08_redos_immunity_and_ec_mime_01_to_05() -> None:
    """Verifica ausencia de ReDoS con URLs gigantes y parseo MIME roto/solo-HTML/deduplicado."""
    giant_url = "https://evil-cargo.com/" + ("a" * 60000)
    raw_mime = (
        b"From: =?iso-8859-1?Q?Aduana_Chacao?= <info@cargo.com>\r\n"
        b"Subject: =?utf-8?B?R3XDrWEgcmV0ZW5pZGE=?=\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<html><body>"
        b'<a href="https://maersk.com/track">Track 1</a>'
        b'<a href="https://maersk.com/track">Track Duplicado</a>'
        b'<a href="' + giant_url.encode("ascii") + b'">Enlace Gigante</a>'
        b"<script>var x = 'http://ignore-script.com';</script>"
        b"</body></html>"
    )

    start = time.perf_counter()
    parsed = parse_raw_email(raw_mime, max_urls_per_email=10, max_url_length=2048)
    elapsed = time.perf_counter() - start

    # Inmunidad ReDoS: debe tardar menos de 0.2 segundos incluso con 60.000 caracteres
    assert elapsed < 0.2
    # EC-MIME-01: Generó Message-ID sintético determinista
    assert parsed.message_id.startswith("<synthetic-")
    # EC-MIME-02: Decodificó correctamente UTF-8 Base64 ("Guía retenida")
    assert "Guía retenida" in parsed.subject
    # EC-MIME-05: Deduplicó https://maersk.com/track e ignoró el <script>
    assert len(parsed.links) == 2
    assert len(parsed.links[1].url) == 2048
