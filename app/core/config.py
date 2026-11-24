"""
Carga funcional e inmutable de variables de entorno y parámetros de riesgo.
Cumple con OWASP ASVS V14 (Configuración Segura) sin utilizar clases.
"""

import os
from functools import lru_cache
from typing import Mapping, Optional
from dotenv import load_dotenv
from app.core.types import AppConfig, make_secret

# Constantes inmutables (tuplas puras) para el contexto aduanero de Chacao
DEFAULT_PROTECTED_DOMAINS: tuple[str, ...] = (
    "maersk.com",
    "msc.com",
    "cma-cgm.com",
    "hapag-lloyd.com",
    "dhl.com",
    "fedex.com",
    "ups.com",
    "grupozoom.com",
    "tealca.com",
    "mrwve.com",
    "seniat.gob.ve",
    "bolipuertos.gob.ve",
    "ine.gob.ve",
)

DEFAULT_CUSTOMS_KEYWORDS: tuple[str, ...] = (
    "guia retenida",
    "guía retenida",
    "manifiesto de carga",
    "bill of lading",
    "conocimiento de embarque",
    "pago de aranceles",
    "liberacion de contenedor",
    "liberación de contenedor",
    "factura aduanera",
    "factura pendiente",
    "seniat",
    "bolipuertos",
    "swift bancario",
    "comprobante de transferencia",
    "pago urgente",
    "embarque detenido",
)

DEFAULT_URL_SHORTENERS: tuple[str, ...] = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
)


def parse_bounded_int(raw_val: Optional[str], default: int, min_val: int, max_val: int, name: str) -> int:
    """Función pura que convierte y valida enteros dentro de rangos estrictos."""
    if raw_val is None or raw_val.strip() == "":
        return default
    try:
        parsed = int(raw_val.strip())
    except ValueError as exc:
        raise ValueError(f"Configuración inválida en {name}: se esperaba un entero.") from exc

    if parsed < min_val or parsed > max_val:
        raise ValueError(
            f"Configuración fuera de rango seguro en {name}: {parsed} (permitido [{min_val}, {max_val}])."
        )
    return parsed


def normalize_db_path(raw_url: str) -> str:
    """Extrae una ruta de archivo segura para sqlite3 nativo a partir de DATABASE_URL."""
    cleaned = raw_url.strip()
    if cleaned.startswith("sqlite:///"):
        return cleaned.replace("sqlite:///", "", 1)
    return cleaned if cleaned else "./phishguard.db"


def build_config_from_mapping(env_map: Mapping[str, str]) -> AppConfig:
    """
    Función pura determinista: transforma un mapa clave-valor en un AppConfig inmutable.
    Facilita las pruebas unitarias sin mutar os.environ.
    """
    imap_port = parse_bounded_int(env_map.get("IMAP_PORT"), 993, 1, 65535, "IMAP_PORT")
    check_interval = parse_bounded_int(
        env_map.get("CHECK_INTERVAL_SECONDS"), 15, 10, 3600, "CHECK_INTERVAL_SECONDS"
    )
    vt_rate_limit = parse_bounded_int(
        env_map.get("VT_RATE_LIMIT_SECONDS"), 16, 1, 120, "VT_RATE_LIMIT_SECONDS"
    )
    suspicious_threshold = parse_bounded_int(
        env_map.get("RISK_THRESHOLD_SUSPICIOUS"), 30, 1, 99, "RISK_THRESHOLD_SUSPICIOUS"
    )
    quarantine_threshold = parse_bounded_int(
        env_map.get("RISK_THRESHOLD_QUARANTINE"), 60, 1, 100, "RISK_THRESHOLD_QUARANTINE"
    )

    if suspicious_threshold >= quarantine_threshold:
        raise ValueError("RISK_THRESHOLD_SUSPICIOUS debe ser estrictamente menor que RISK_THRESHOLD_QUARANTINE.")

    quarantine_folder = env_map.get("QUARANTINE_FOLDER", "Cuarentena").strip()
    if any(ch in quarantine_folder for ch in ("\r", "\n", "\x00")) or not quarantine_folder:
        raise ValueError("QUARANTINE_FOLDER contiene caracteres de control prohibidos o está vacío.")

    return AppConfig(
        project_name="Monitor y Filtro de Enlaces Maliciosos - Chacao",
        version="1.0.0",
        imap_server=env_map.get("IMAP_SERVER", "imap.gmail.com").strip(),
        imap_port=imap_port,
        email_user=env_map.get("EMAIL_USER", "").strip(),
        email_password=make_secret(env_map.get("EMAIL_PASSWORD", "")),
        quarantine_folder=quarantine_folder,
        check_interval_seconds=check_interval,
        virustotal_api_key=make_secret(env_map.get("VIRUSTOTAL_API_KEY", "")),
        vt_rate_limit_seconds=vt_rate_limit,
        urlhaus_feed_url=env_map.get(
            "URLHAUS_FEED_URL", "https://openphish.com/feed.txt"
        ).strip(),
        database_path=normalize_db_path(env_map.get("DATABASE_URL", "sqlite:///./phishguard.db")),
        risk_threshold_suspicious=suspicious_threshold,
        risk_threshold_quarantine=quarantine_threshold,
        max_email_bytes=10 * 1024 * 1024,  # Tope anti-DoS: 10 MB por correo
        max_urls_per_email=50,             # Tope anti-DoS: máx 50 enlaces únicos por mensaje
        max_url_length=2048,               # Tope RFC / anti-ReDoS: 2048 caracteres
        protected_logistics_domains=DEFAULT_PROTECTED_DOMAINS,
        customs_phishing_keywords=DEFAULT_CUSTOMS_KEYWORDS,
        url_shorteners=DEFAULT_URL_SHORTENERS,
    )


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """Cáscara imperativa mínima: carga .env una sola vez y retorna AppConfig congelado."""
    load_dotenv()
    return build_config_from_mapping(os.environ)
