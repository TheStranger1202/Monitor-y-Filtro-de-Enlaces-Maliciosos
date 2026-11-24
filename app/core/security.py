"""
Funciones puras de seguridad transversal alineadas con OWASP Top 10 y ASVS.
Prevención de Log Injection (CWE-117), Defanging de URLs y cabeceras HTTP seguras.
"""

import re

# Expresión regular lineal precompilada (libre de backtracking catastrófico) para caracteres de control
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")

DANGEROUS_SCHEMES: tuple[str, ...] = ("javascript:", "data:", "vbscript:", "file:")


def sanitize_for_log(raw_text: str, max_len: int = 250) -> str:
    """
    Función pura que elimina saltos de línea (CRLF), bytes nulos y caracteres de control
    para impedir ataques de Log Injection / Log Forgery (CWE-117 / EC-LOG-01).
    """
    if not raw_text:
        return ""
    cleaned = _CONTROL_CHARS_RE.sub(" ", str(raw_text)).strip()
    if len(cleaned) > max_len:
        return f"{cleaned[:max_len]}...[TRUNCATED]"
    return cleaned


def has_dangerous_scheme(url: str) -> bool:
    """
    Función pura que detecta esquemas ejecutables maliciosos como `javascript:` o `data:` (EC-XSS-02).
    """
    normalized = _CONTROL_CHARS_RE.sub("", str(url)).strip().lower()
    return normalized.startswith(DANGEROUS_SCHEMES)


def defang_url(url: str) -> str:
    """
    Función pura que neutraliza visualmente una URL hostil para que jamás sea clicable
    ni ejecutable por accidente en paneles de auditoría o reportes.
    Ejemplo: 'https://evil.com/login' -> 'hxxps://evil[.]com/login'
    """
    if not url:
        return ""
    cleaned = sanitize_for_log(url, max_len=2048)
    lowered = cleaned.lower()

    if lowered.startswith("javascript:"):
        cleaned = "blocked-javascript:" + cleaned[11:]
    elif lowered.startswith("data:"):
        cleaned = "blocked-data:" + cleaned[5:]
    elif lowered.startswith("vbscript:"):
        cleaned = "blocked-vbscript:" + cleaned[9:]
    elif lowered.startswith("https://"):
        cleaned = "hxxps://" + cleaned[8:]
    elif lowered.startswith("http://"):
        cleaned = "hxxp://" + cleaned[7:]

    return cleaned.replace(".", "[.]")


def get_owasp_security_headers() -> tuple[tuple[str, str], ...]:
    """
    Retorna una tupla inmutable de cabeceras HTTP recomendadas por OWASP ASVS
    para proteger el Dashboard contra Blind Stored XSS, Clickjacking y MIME Sniffing.
    """
    return (
        (
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
        ("Cache-Control", "no-store, max-age=0"),
    )
