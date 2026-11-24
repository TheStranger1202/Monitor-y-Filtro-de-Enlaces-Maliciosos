"""
Servicio puramente funcional para decodificación segura de correos MIME/HTML
y extracción normalizada de enlaces (Cero clases POO).
Mitiga CWE-1333 (ReDoS), EC-MIME-01..05 y EC-URL-01..08.
"""

import hashlib
import re
from email import message_from_bytes
from email.header import decode_header
from email.message import Message
from urllib.parse import urlsplit
from bs4 import BeautifulSoup

from app.core.security import has_dangerous_scheme
from app.core.types import ExtractedLink, ParsedEmail

# Regex lineal sin cuantificadores anidados ambiguos (inmune a ReDoS - CWE-1333)
_PLAIN_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?)]}>\"'"


def decode_mime_header_safe(raw_header: str | None) -> str:
    """
    Función pura que decodifica cabeceras RFC 2047 (UTF-8, ISO-8859-1, Base64, Q-Encoding)
    sin fallar ante bytes corruptos (EC-MIME-02).
    """
    if not raw_header:
        return ""
    parts: list[str] = []
    try:
        decoded_chunks = decode_header(raw_header)
    except Exception:
        return str(raw_header).strip()

    for content, charset in decoded_chunks:
        if isinstance(content, bytes):
            enc = charset or "utf-8"
            try:
                parts.append(content.decode(enc, errors="replace"))
            except LookupError:
                parts.append(content.decode("utf-8", errors="replace"))
        else:
            parts.append(str(content))

    return "".join(parts).strip()


def normalize_hostname_to_ascii(raw_host: str | None) -> str:
    """
    Función pura que normaliza un hostname a minúsculas y Punycode ASCII (`xn--...`)
    para neutralizar ataques homográficos IDN (EC-URL-01).
    """
    if not raw_host:
        return ""
    host = raw_host.strip().lower().rstrip(".")
    # Si es IPv6 entre corchetes (urlsplit.hostname ya remueve corchetes, pero aseguramos)
    if ":" in host:
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def extract_domain_safe(url: str, max_url_length: int = 2048) -> str:
    """
    Función pura que extrae el host real de destino de una URL.
    Respeta correctamente el delimitador `@` en URLs con credenciales embebidas (EC-URL-02).
    """
    trimmed = url.strip()[:max_url_length]
    if has_dangerous_scheme(trimmed):
        return "dangerous-scheme.invalid"
    try:
        parsed = urlsplit(trimmed)
    except ValueError:
        return "malformed-url.invalid"

    return normalize_hostname_to_ascii(parsed.hostname)


def extract_links_from_html(
    html_body: str, max_url_length: int = 2048
) -> tuple[tuple[str, str], ...]:
    """
    Extrae pares `(href, visible_text)` desde el DOM HTML usando BeautifulSoup
    y elimina scripts/estilos antes de recuperar enlaces residuales.
    """
    if not html_body:
        return ()

    soup = BeautifulSoup(html_body, "html.parser")
    pairs: list[tuple[str, str]] = []

    for anchor in soup.find_all("a", href=True):
        raw_href = str(anchor.get("href", "")).strip()
        if not raw_href or raw_href.startswith(("#", "mailto:", "tel:", "cid:")):
            continue
        safe_href = raw_href[:max_url_length]
        visible = " ".join(anchor.get_text(separator=" ", strip=True).split())[:512]
        pairs.append((safe_href, visible))

    # También buscar URLs en texto visible del HTML que no estén dentro de <a href>
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    visible_text_all = soup.get_text(separator=" ", strip=True)
    for plain_url in extract_urls_from_text(visible_text_all, max_url_length=max_url_length):
        pairs.append((plain_url, ""))

    return tuple(pairs)


def extract_urls_from_text(text_body: str, max_url_length: int = 2048) -> tuple[str, ...]:
    """
    Extrae URLs HTTP/HTTPS desde texto plano acotando la entrada para prevenir ReDoS (EC-URL-08).
    """
    if not text_body:
        return ()
    # Acotar escaneo de texto plano a 500 KB máximo por seguridad
    bounded_text = text_body[: 500 * 1024]
    found: list[str] = []
    for match in _PLAIN_URL_RE.finditer(bounded_text):
        candidate = match.group(0).rstrip(_TRAILING_PUNCT)[:max_url_length]
        if candidate:
            found.append(candidate)
    return tuple(found)


def html_to_clean_text(html_body: str) -> str:
    """Convierte HTML en texto limpio sin etiquetas `<script>` ni `<style>`."""
    if not html_body:
        return ""
    soup = BeautifulSoup(html_body, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return " ".join(soup.get_text(separator=" ", strip=True).split())


def _decode_part_payload(part: Message, max_bytes: int) -> str:
    """Extrae y decodifica de forma segura el payload de una parte MIME."""
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return ""
    bounded = payload[:max_bytes]
    charset = part.get_content_charset() or "utf-8"
    try:
        return bounded.decode(charset, errors="replace")
    except LookupError:
        return bounded.decode("utf-8", errors="replace")


def parse_raw_email(
    raw_bytes: bytes,
    max_email_bytes: int = 10 * 1024 * 1024,
    max_urls_per_email: int = 50,
    max_url_length: int = 2048,
) -> ParsedEmail:
    """
    Función pura principal de ingesta: transforma bytes MIME crudos en un `ParsedEmail` inmutable.
    Maneja ausencia de Message-ID (EC-MIME-01), correos solo HTML (EC-MIME-03),
    tamaño excesivo (EC-MIME-04) y deduplicación de enlaces (EC-MIME-05).
    """
    bounded_raw = raw_bytes[:max_email_bytes]
    msg = message_from_bytes(bounded_raw)

    raw_msg_id = decode_mime_header_safe(msg.get("Message-ID"))
    if raw_msg_id:
        message_id = raw_msg_id
    else:
        digest = hashlib.sha256(bounded_raw).hexdigest()[:32]
        message_id = f"<synthetic-{digest}@phishguard.local>"

    sender = decode_mime_header_safe(msg.get("From")) or "unknown@unknown.invalid"
    subject = decode_mime_header_safe(msg.get("Subject")) or "(Sin asunto)"

    plain_chunks: list[str] = []
    html_chunks: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disposition = str(part.get("Content-Disposition", "")).lower()
            if "attachment" in disposition:
                continue
            ctype = part.get_content_type().lower()
            if ctype == "text/plain":
                plain_chunks.append(_decode_part_payload(part, max_email_bytes))
            elif ctype == "text/html":
                html_chunks.append(_decode_part_payload(part, max_email_bytes))
    else:
        ctype = msg.get_content_type().lower()
        if ctype == "text/html":
            html_chunks.append(_decode_part_payload(msg, max_email_bytes))
        else:
            plain_chunks.append(_decode_part_payload(msg, max_email_bytes))

    combined_html = "\n".join(html_chunks)
    combined_plain = "\n".join(plain_chunks).strip()
    if not combined_plain and combined_html:
        combined_plain = html_to_clean_text(combined_html)

    raw_candidates: list[tuple[str, str]] = []
    if combined_html:
        raw_candidates.extend(extract_links_from_html(combined_html, max_url_length=max_url_length))
    for text_url in extract_urls_from_text(combined_plain, max_url_length=max_url_length):
        raw_candidates.append((text_url, ""))

    # Deduplicación preservando el primer texto visible no vacío encontrado (EC-MIME-05)
    dedup_map: dict[str, tuple[str, str]] = {}
    for candidate_url, vis_text in raw_candidates:
        norm_key = candidate_url.strip()
        if not norm_key:
            continue
        if norm_key not in dedup_map:
            if len(dedup_map) >= max_urls_per_email:
                break
            dedup_map[norm_key] = (norm_key, vis_text)
        elif not dedup_map[norm_key][1] and vis_text:
            dedup_map[norm_key] = (norm_key, vis_text)

    extracted_links = tuple(
        ExtractedLink(
            url=u,
            visible_text=v,
            domain=extract_domain_safe(u, max_url_length=max_url_length),
        )
        for u, v in dedup_map.values()
    )

    return ParsedEmail(
        message_id=message_id,
        sender=sender,
        subject=subject,
        plain_text=combined_plain[: 100 * 1024],
        links=extracted_links,
    )
