"""
Punto de entrada funcional de FastAPI (Cero Clases POO).
Gestiona el ciclo de vida del monitor IMAP en segundo plano,
las cabeceras HTTP de seguridad OWASP y el manejo seguro de excepciones.
"""

import asyncio
from contextlib import asynccontextmanager
import logging
from typing import AsyncIterator, Callable
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api.routes import create_api_router
from app.core.config import get_config
from app.core.security import get_owasp_security_headers, sanitize_for_log
from app.core.types import AppConfig, VtLayerResult
from app.db.database import init_database
from app.services.detection.vt_layer import make_rate_limiter, query_virustotal_url
from app.services.imap_service import poll_inbox_once

logger = logging.getLogger("phishguard.main")


def build_vt_query_fn(config: AppConfig) -> Callable[[str], VtLayerResult] | None:
    """Construye la función de consulta VirusTotal con Rate Limiter si existe API Key."""
    if not config.virustotal_api_key.reveal().strip():
        return None
    wait_fn = make_rate_limiter(float(config.vt_rate_limit_seconds))
    return lambda url: query_virustotal_url(
        url=url,
        api_key_secret=config.virustotal_api_key,
        rate_limit_wait_fn=wait_fn,
    )


async def run_imap_background_loop(
    config: AppConfig,
    vt_query_fn: Callable[[str], VtLayerResult] | None,
    stop_event: asyncio.Event,
) -> None:
    """Ejecuta el sondeo IMAP en un hilo separado para no bloquear el event loop de FastAPI."""
    while not stop_event.is_set():
        try:
            await asyncio.to_thread(poll_inbox_once, config, vt_query_fn)
        except Exception as exc:
            logger.error("Fallo inesperado en ciclo IMAP: %s", sanitize_for_log(str(exc)))
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=float(config.check_interval_seconds))
        except asyncio.TimeoutError:
            continue


def create_app(
    config: AppConfig | None = None,
    enable_imap_worker: bool = True,
    vt_query_fn: Callable[[str], VtLayerResult] | None = None,
) -> FastAPI:
    """
    Fábrica funcional de la aplicación FastAPI.
    Permite inyectar configuración y desactivar el worker IMAP durante pruebas unitarias.
    """
    active_config = config or get_config()
    active_vt_fn = vt_query_fn if vt_query_fn is not None else build_vt_query_fn(active_config)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        init_database(active_config.database_path)
        stop_event = asyncio.Event()
        worker_task: asyncio.Task[None] | None = None

        has_imap_creds = bool(
            active_config.email_user.strip() and active_config.email_password.reveal().strip()
        )
        if enable_imap_worker and has_imap_creds:
            worker_task = asyncio.create_task(
                run_imap_background_loop(active_config, active_vt_fn, stop_event)
            )
            logger.info("Monitor IMAP iniciado en segundo plano.")

        try:
            yield
        finally:
            stop_event.set()
            if worker_task is not None:
                worker_task.cancel()
                try:
                    await worker_task
                except asyncio.CancelledError:
                    pass

    app = FastAPI(
        title=active_config.project_name,
        version=active_config.version,
        docs_url="/api/docs",
        redoc_url=None,
        lifespan=lifespan,
    )

    security_headers = get_owasp_security_headers()

    @app.middleware("http")
    async def inject_owasp_headers(request: Request, call_next: Callable):
        response = await call_next(request)
        for header_name, header_value in security_headers:
            response.headers[header_name] = header_value
        return response

    @app.exception_handler(Exception)
    async def safe_unhandled_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
        logger.error("Excepción no controlada: %s", sanitize_for_log(str(exc)))
        return JSONResponse(
            status_code=500,
            content={"detail": "Error interno del servidor."},
        )

    app.include_router(create_api_router(active_config, vt_query_fn=active_vt_fn))
    return app


app = create_app()
