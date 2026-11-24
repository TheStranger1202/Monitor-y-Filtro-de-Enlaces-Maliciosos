"""
Capa 2 del Motor Híbrido:
Consulta segura a VirusTotal API v3 sin visitar jamás la URL sospechosa (Anti-SSRF).
Incluye Rate Limiter mediante clausura léxica y degradación elegante (EC-EXT-01..03).
"""

import base64
import time
from typing import Callable
import httpx

from app.core.security import has_dangerous_scheme
from app.core.types import SecretValue, VtLayerResult

VT_API_BASE_URL = "https://www.virustotal.com/api/v3/urls"


def encode_vt_url_id(url: str) -> str:
    """
    Función pura que genera el identificador URL-safe Base64 sin relleno (`=`)
    exigido por el endpoint `/api/v3/urls/{id}` de VirusTotal v3.
    """
    raw_bytes = url.strip().encode("utf-8", errors="replace")
    return base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")


def make_rate_limiter(
    min_interval_seconds: float,
    clock_fn: Callable[[], float] = time.monotonic,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> Callable[[], None]:
    """
    Clausura funcional pura para control de tasa (Rate Limiting).
    Garantiza un intervalo mínimo entre peticiones sucesivas a VirusTotal.
    """
    state: list[float | None] = [None]

    def _wait_if_needed() -> None:
        now = clock_fn()
        last = state[0]
        if last is not None:
            elapsed = now - last
            remaining = min_interval_seconds - elapsed
            if remaining > 0:
                sleep_fn(remaining)
        state[0] = clock_fn()

    return _wait_if_needed


def parse_vt_json_payload(payload: object) -> VtLayerResult:
    """
    Función pura defensiva que valida la estructura JSON devuelta por VirusTotal
    sin asumir que las claves existen (mitiga EC-EXT-03).
    """
    if not isinstance(payload, dict):
        return VtLayerResult(0, 0, error="invalid_vt_json_root")

    data = payload.get("data")
    if not isinstance(data, dict):
        return VtLayerResult(0, 0, error="missing_vt_data_field")

    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        return VtLayerResult(0, 0, error="missing_vt_attributes_field")

    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return VtLayerResult(0, 0, error="missing_vt_stats_field")

    try:
        malicious = max(0, int(stats.get("malicious", 0)))
        suspicious = max(0, int(stats.get("suspicious", 0)))
    except (TypeError, ValueError):
        return VtLayerResult(0, 0, error="malformed_vt_stat_counters")

    return VtLayerResult(malicious_count=malicious, suspicious_count=suspicious, error="")


def query_virustotal_url(
    url: str,
    api_key_secret: SecretValue,
    rate_limit_wait_fn: Callable[[], None] | None = None,
    timeout_seconds: float = 8.0,
    http_get_fn: Callable[..., httpx.Response] | None = None,
) -> VtLayerResult:
    """
    Cáscara imperativa acotada que consulta VirusTotal v3 por HTTPS estricto.
    Maneja errores 404, 429, 5xx y timeouts devolviendo siempre un `VtLayerResult` válido.
    """
    clean_url = url.strip()
    if not clean_url or has_dangerous_scheme(clean_url):
        return VtLayerResult(0, 0, error="skipped_non_http_url")

    api_key = api_key_secret.reveal().strip()
    if not api_key:
        return VtLayerResult(0, 0, error="vt_api_key_not_configured")

    if rate_limit_wait_fn is not None:
        rate_limit_wait_fn()

    url_id = encode_vt_url_id(clean_url)
    endpoint = f"{VT_API_BASE_URL}/{url_id}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        if http_get_fn is not None:
            response = http_get_fn(endpoint, headers=headers, timeout=timeout_seconds)
        else:
            with httpx.Client(verify=True, follow_redirects=False, timeout=timeout_seconds) as client:
                response = client.get(endpoint, headers=headers)
    except httpx.TimeoutException:
        return VtLayerResult(0, 0, error="vt_timeout")
    except httpx.HTTPError:
        return VtLayerResult(0, 0, error="vt_network_error")
    except Exception:
        return VtLayerResult(0, 0, error="vt_unexpected_error")

    status = response.status_code
    if status == 404:
        # URL desconocida para VirusTotal: no es un fallo, simplemente aún no tiene detecciones
        return VtLayerResult(0, 0, error="vt_url_not_found")
    if status == 429:
        return VtLayerResult(0, 0, error="vt_rate_limited_429")
    if status in (401, 403):
        return VtLayerResult(0, 0, error="vt_auth_error")
    if status >= 500:
        return VtLayerResult(0, 0, error=f"vt_server_error_{status}")
    if status != 200:
        return VtLayerResult(0, 0, error=f"vt_unexpected_status_{status}")

    try:
        json_data = response.json()
    except ValueError:
        return VtLayerResult(0, 0, error="vt_invalid_json")

    return parse_vt_json_payload(json_data)
