"""
Script funcional de actualización de Inteligencia de Amenazas Local (OpenPhish / URLhaus).
Soporta automáticamente feeds en texto plano (1 URL por línea) y formato CSV.
Protegido contra Stream Bombs (EC-EXT-04), SSRF de esquema no HTTPS y filas corruptas.
"""

import csv
import io
import logging
from typing import Callable
import httpx

from app.core.config import get_config
from app.core.security import sanitize_for_log
from app.db.database import init_database, insert_threat_feed_batch, open_db_connection
from app.services.parser_service import extract_domain_safe

logger = logging.getLogger("phishguard.feeds")


def download_feed_bounded(
    feed_url: str,
    max_bytes: int = 15 * 1024 * 1024,
    timeout_seconds: float = 20.0,
) -> str:
    """
    Descarga un feed remoto exigiendo HTTPS estricto y abortando inmediatamente
    si la respuesta excede `max_bytes` (prevención de agotamiento de RAM - EC-EXT-04).
    """
    clean_url = feed_url.strip()
    if not clean_url.lower().startswith("https://"):
        raise ValueError("Solo se permiten orígenes HTTPS verificados para feeds de amenazas.")

    chunks: list[bytes] = []
    downloaded = 0

    with httpx.Client(verify=True, follow_redirects=True, timeout=timeout_seconds) as client:
        with client.stream("GET", clean_url) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes(chunk_size=65536):
                downloaded += len(chunk)
                if downloaded > max_bytes:
                    raise ValueError(
                        f"El feed superó el tamaño máximo permitido de {max_bytes} bytes."
                    )
                chunks.append(chunk)

    return b"".join(chunks).decode("utf-8", errors="replace")


def parse_plain_text_feed(
    raw_text: str, source: str = "openphish", max_entries: int = 25000
) -> tuple[tuple[str, str, str, str], ...]:
    """
    Función pura que parsea feeds en texto plano (1 URL por línea, ej. OpenPhish)
    devolviendo tuplas `(url, domain, 'phishing', source)`.
    """
    if not raw_text:
        return ()

    entries: list[tuple[str, str, str, str]] = []
    for line in io.StringIO(raw_text):
        candidate_url = line.strip()[:2048]
        if not candidate_url or candidate_url.startswith("#"):
            continue
        if not candidate_url.lower().startswith(("http://", "https://")):
            continue
        domain = extract_domain_safe(candidate_url)
        if not domain or domain.endswith(".invalid"):
            continue
        entries.append((candidate_url, domain, "phishing", source))
        if len(entries) >= max_entries:
            break

    return tuple(entries)


def parse_urlhaus_csv(
    raw_csv_text: str, max_entries: int = 25000
) -> tuple[tuple[str, str, str, str], ...]:
    """
    Función pura que parsea el formato CSV de URLhaus ignorando comentarios `#`
    y extrayendo tuplas `(url, domain, threat_type, 'urlhaus')`.
    """
    if not raw_csv_text:
        return ()

    uncommented_lines = (
        line for line in io.StringIO(raw_csv_text) if line.strip() and not line.lstrip().startswith("#")
    )
    reader = csv.reader(uncommented_lines)
    entries: list[tuple[str, str, str, str]] = []

    for row in reader:
        if len(row) < 6:
            continue
        candidate_url = row[2].strip()[:2048]
        if not candidate_url.lower().startswith(("http://", "https://")):
            continue
        domain = extract_domain_safe(candidate_url)
        if not domain or domain.endswith(".invalid"):
            continue
        threat_type = (row[5].strip() or "malware_or_phishing")[:64]
        entries.append((candidate_url, domain, threat_type, "urlhaus"))
        if len(entries) >= max_entries:
            break

    return tuple(entries)


def parse_threat_feed_auto(
    raw_text: str, max_entries: int = 25000
) -> tuple[tuple[str, str, str, str], ...]:
    """
    Función pura que detecta automáticamente si el feed es texto plano (OpenPhish)
    o CSV estructurado (URLhaus).
    """
    if not raw_text:
        return ()

    for line in io.StringIO(raw_text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.lower().startswith(("http://", "https://")) and "," not in stripped:
            return parse_plain_text_feed(raw_text, source="openphish", max_entries=max_entries)
        return parse_urlhaus_csv(raw_text, max_entries=max_entries)

    return ()


def sync_urlhaus_feed(
    db_path: str,
    feed_url: str,
    downloader_fn: Callable[[str], str] = download_feed_bounded,
) -> int:
    """Descarga, parsea automáticamente e inserta en lote las amenazas dentro de SQLite."""
    init_database(db_path)
    raw_content = downloader_fn(feed_url)
    parsed_entries = parse_threat_feed_auto(raw_content)
    if not parsed_entries:
        return 0

    with open_db_connection(db_path) as conn:
        inserted = insert_threat_feed_batch(conn, parsed_entries)
    return inserted


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    cfg = get_config()
    try:
        inserted = sync_urlhaus_feed(cfg.database_path, cfg.urlhaus_feed_url)
        logger.info("Feed de amenazas sincronizado correctamente. Nuevos indicadores: %d", inserted)
    except Exception as exc:
        logger.error("Error al sincronizar feed de amenazas: %s", sanitize_for_log(str(exc)))
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
