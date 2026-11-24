"""
Definiciones de tipos inmutables mediante programación funcional pura (cero clases).
Utiliza constructores funcionales `namedtuple` y clausuras léxicas para secretos.
"""

from collections import namedtuple
from typing import Callable

# Contenedor inmutable para secretos: `masked` siempre vale '********' en repr/str/logs,
# mientras que `reveal` es una clausura pura (() -> str) que devuelve el secreto real.
SecretValue = namedtuple("SecretValue", ["masked", "reveal"])


def make_secret(raw_value: str) -> SecretValue:
    """
    Encapsula una credencial sensible dentro de una clausura léxica privada.
    Evita fugas accidentales en logs, prints o tracebacks (OWASP A09 / CWE-532).
    """
    clean_secret = str(raw_value)

    def _reveal() -> str:
        return clean_secret

    return SecretValue(masked="********", reveal=_reveal)


# Configuración global inmutable de la aplicación
AppConfig = namedtuple(
    "AppConfig",
    [
        "project_name",
        "version",
        "imap_server",
        "imap_port",
        "email_user",
        "email_password",
        "quarantine_folder",
        "check_interval_seconds",
        "virustotal_api_key",
        "vt_rate_limit_seconds",
        "urlhaus_feed_url",
        "database_path",
        "risk_threshold_suspicious",
        "risk_threshold_quarantine",
        "max_email_bytes",
        "max_urls_per_email",
        "max_url_length",
        "protected_logistics_domains",
        "customs_phishing_keywords",
        "url_shorteners",
    ],
)

# Estructuras inmutables para el flujo de correo y extracción
ExtractedLink = namedtuple("ExtractedLink", ["url", "visible_text", "domain"])

ParsedEmail = namedtuple(
    "ParsedEmail",
    [
        "message_id",
        "sender",
        "subject",
        "plain_text",
        "links",  # tuple[ExtractedLink, ...]
    ],
)

# Estructuras inmutables para las 3 capas de detección
LocalLayerResult = namedtuple("LocalLayerResult", ["status", "reason"])
VtLayerResult = namedtuple("VtLayerResult", ["malicious_count", "suspicious_count", "error"])
HeuristicResult = namedtuple("HeuristicResult", ["score", "reasons"])

# Resultado consolidado inmutable por URL y por correo
UrlVerdict = namedtuple(
    "UrlVerdict",
    [
        "original_url",
        "defanged_url",
        "visible_text",
        "domain",
        "layer1_status",
        "vt_malicious_count",
        "vt_suspicious_count",
        "heuristic_score",
        "heuristic_reasons",  # tuple[str, ...]
        "final_score",
        "verdict",  # 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
    ],
)

EmailRecord = namedtuple(
    "EmailRecord",
    [
        "id",
        "message_id",
        "sender",
        "subject",
        "received_at",
        "processed_at",
        "max_risk_score",
        "status",
        "quarantined",
    ],
)

DashboardStats = namedtuple(
    "DashboardStats",
    [
        "total_emails",
        "clean_emails",
        "suspicious_emails",
        "quarantined_emails",
        "total_malicious_urls",
    ],
)

# Tipo funcional para inyección de funciones de consulta
UrlLookupFn = Callable[[str], str]
