"""
Servicio Funcional de Monitoreo IMAP y Remediación en Cuarentena.
Implementa TLS estricto, validación contra IMAP Command Injection (EC-IMAP-01)
y traslado seguro sin pérdida de mensajes (EC-IMAP-02, EC-IMAP-03).
"""

import imaplib
import logging
import re
import ssl
from typing import Any, Callable

from app.core.security import sanitize_for_log
from app.core.types import AppConfig, VtLayerResult
from app.db.database import (
    fetch_whitelisted_domains,
    is_email_already_processed,
    is_url_or_domain_blacklisted,
    open_db_connection,
    save_email_analysis,
)
from app.services.detection.engine import evaluate_parsed_email
from app.services.parser_service import parse_raw_email

logger = logging.getLogger("phishguard.imap")

_SAFE_UID_RE = re.compile(r"^[0-9]{1,20}$")
_SAFE_FOLDER_RE = re.compile(r"^[a-zA-Z0-9_\-/ ]{1,64}$")


def validate_imap_uid(uid: str | bytes) -> str:
    """
    Función pura que valida estrictamente que un UID IMAP sea numérico positivo.
    Bloquea cualquier intento de IMAP Command Injection (CWE-93 / EC-IMAP-01).
    """
    text = uid.decode("ascii", errors="strict") if isinstance(uid, bytes) else str(uid)
    cleaned = text.strip()
    if not _SAFE_UID_RE.match(cleaned):
        raise ValueError("UID IMAP inválido o potencialmente malicioso rechazado.")
    return cleaned


def validate_imap_folder_name(folder: str) -> str:
    """
    Función pura que valida el nombre del buzón de cuarentena rechazando CRLF,
    comillas, caracteres de control o comodines IMAP (`*`, `%`).
    """
    cleaned = str(folder).strip()
    if not _SAFE_FOLDER_RE.match(cleaned):
        raise ValueError("Nombre de carpeta IMAP inseguro rechazado.")
    return f'"{cleaned}"' if " " in cleaned else cleaned


def create_secure_imap_connection(config: AppConfig, timeout: float = 15.0) -> imaplib.IMAP4_SSL:
    """Abre y autentica una sesión `IMAP4_SSL` verificando certificados TLS del sistema."""
    user = config.email_user.strip()
    password = config.email_password.reveal()
    if not user or not password:
        raise RuntimeError("Credenciales IMAP no configuradas en variables de entorno.")

    tls_context = ssl.create_default_context()
    imap_conn = imaplib.IMAP4_SSL(
        host=config.imap_server,
        port=config.imap_port,
        ssl_context=tls_context,
        timeout=timeout,
    )
    imap_conn.login(user, password)
    return imap_conn


def ensure_quarantine_folder_exists(imap_conn: Any, quarantine_folder: str) -> str:
    """
    Garantiza que la carpeta `Cuarentena` exista en el servidor IMAP antes de mover mensajes (EC-IMAP-02).
    Retorna el nombre sanitizado listo para comandos IMAP.
    """
    safe_folder = validate_imap_folder_name(quarantine_folder)
    status, mailboxes = imap_conn.list()
    if status == "OK" and mailboxes:
        raw_target = quarantine_folder.strip().lower()
        for entry in mailboxes:
            decoded = entry.decode("utf-8", errors="ignore").lower() if isinstance(entry, bytes) else str(entry).lower()
            if f'"{raw_target}"' in decoded or decoded.endswith(f" {raw_target}") or decoded.endswith(f"/{raw_target}"):
                return safe_folder

    # Si no se encontró en LIST, solicitar su creación (idempotente si ya existía)
    imap_conn.create(safe_folder)
    return safe_folder


def extract_raw_bytes_from_fetch(fetch_data: list[Any] | None) -> bytes | None:
    """Extrae de forma segura el cuerpo RFC822 en bytes desde la respuesta de `uid('FETCH', ...)`."""
    if not fetch_data:
        return None
    for item in fetch_data:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
            return item[1]
    return None


def quarantine_message_by_uid(imap_conn: Any, uid: str, quarantine_folder: str) -> bool:
    r"""
    Traslada un mensaje malicioso hacia `Cuarentena` usando `UID COPY` + `\\Deleted` + `EXPUNGE`.
    Jamás marca un correo para borrado si `UID COPY` no confirmó `'OK'` (cero pérdida de correos).
    """
    safe_uid = validate_imap_uid(uid)
    safe_folder = ensure_quarantine_folder_exists(imap_conn, quarantine_folder)

    copy_status, _ = imap_conn.uid("COPY", safe_uid, safe_folder)
    if copy_status != "OK":
        logger.error("Fallo al copiar UID %s a %s; se aborta borrado por seguridad.", safe_uid, safe_folder)
        return False

    store_status, _ = imap_conn.uid("STORE", safe_uid, "+FLAGS.SILENT", "(\\Deleted)")
    if store_status == "OK":
        imap_conn.expunge()
    return True


def poll_inbox_once(
    config: AppConfig,
    vt_query_fn: Callable[[str], VtLayerResult] | None = None,
    imap_factory_fn: Callable[[AppConfig], Any] = create_secure_imap_connection,
    max_messages_per_cycle: int = 15,
) -> tuple[int, int]:
    """
    Ejecuta un ciclo atómico de monitoreo sobre `INBOX`:
    1. Conecta vía IMAP TLS (y cierra limpio en `finally` ante caídas - EC-IMAP-03).
    2. Descarga solo el cuerpo en modo `BODY.PEEK[]` para no alterar el estado de lectura de correos limpios.
    3. Verifica idempotencia en SQLite, ejecuta el motor de 3 capas y mueve a Cuarentena si supera el umbral.
    Retorna `(correos_analizados_nuevos, correos_enviados_a_cuarentena)`.
    """
    analyzed_count = 0
    quarantined_count = 0
    imap_conn = None

    try:
        imap_conn = imap_factory_fn(config)
        sel_status, _ = imap_conn.select("INBOX")
        if sel_status != "OK":
            logger.warning("No fue posible seleccionar INBOX.")
            return (0, 0)

        search_status, search_data = imap_conn.uid("SEARCH", None, "UNSEEN")
        if search_status != "OK" or not search_data or not search_data[0]:
            return (0, 0)

        raw_uids = search_data[0].split()
        # Procesar los más recientes primero acotando el lote por ciclo
        recent_uids = raw_uids[-max_messages_per_cycle:]

        for raw_uid in recent_uids:
            safe_uid = validate_imap_uid(raw_uid)
            # BODY.PEEK[] lee los bytes sin marcar el correo como leído (\Seen) en correos seguros
            fetch_status, fetch_data = imap_conn.uid("FETCH", safe_uid, "(BODY.PEEK[])")
            if fetch_status != "OK":
                continue

            raw_email = extract_raw_bytes_from_fetch(fetch_data)
            if not raw_email:
                continue

            parsed = parse_raw_email(
                raw_email,
                max_email_bytes=config.max_email_bytes,
                max_urls_per_email=config.max_urls_per_email,
                max_url_length=config.max_url_length,
            )

            with open_db_connection(config.database_path) as db_conn:
                if is_email_already_processed(db_conn, parsed.message_id):
                    continue

                whitelist = fetch_whitelisted_domains(db_conn)
                max_score, email_status, should_quarantine, verdicts = evaluate_parsed_email(
                    parsed_email=parsed,
                    config=config,
                    whitelisted_domains=whitelist,
                    is_blacklisted_fn=lambda u, d: is_url_or_domain_blacklisted(db_conn, u, d),
                    vt_query_fn=vt_query_fn,
                )

                moved_ok = False
                if should_quarantine:
                    moved_ok = quarantine_message_by_uid(
                        imap_conn, safe_uid, config.quarantine_folder
                    )
                    if moved_ok:
                        quarantined_count += 1

                final_status = "QUARANTINED" if moved_ok else (
                    "SUSPICIOUS" if should_quarantine else email_status
                )

                save_email_analysis(
                    conn=db_conn,
                    message_id=parsed.message_id,
                    sender=parsed.sender,
                    subject=parsed.subject,
                    max_risk_score=max_score,
                    status=final_status,
                    quarantined=moved_ok,
                    verdicts=verdicts,
                )
                analyzed_count += 1
                logger.info(
                    "Correo procesado msg_id=%s score=%d status=%s",
                    sanitize_for_log(parsed.message_id, 80),
                    max_score,
                    final_status,
                )

    except (imaplib.IMAP4.error, OSError) as exc:
        logger.warning("Error controlado de red/IMAP (EC-IMAP-03): %s", sanitize_for_log(str(exc)))
    finally:
        if imap_conn is not None:
            try:
                imap_conn.logout()
            except Exception:
                pass

    return (analyzed_count, quarantined_count)
