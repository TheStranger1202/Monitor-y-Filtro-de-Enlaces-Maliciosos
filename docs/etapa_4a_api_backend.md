# Documentación Técnica — Etapa 4A: Backend de la API REST y Ciclo de Vida (FastAPI)

Este documento respalda la implementación funcional (100% libre de clases POO) de los endpoints JSON del Dashboard y el orquestador de ciclo de vida del servidor, completando la **Tarjeta #6 de Trello**.

---

## 1. Trazabilidad con el Tablero del Equipo (Trello)

| Tarjeta de Trello | Módulos Implementados | Estado |
| :--- | :--- | :--- |
| **6. Backend del Dashboard Web** | `app/api/routes.py`, `app/main.py`, `tests/test_etapa4a_api_backend.py` | Completado y probado |

---

## 2. Contrato de Endpoints (`/api/v1`)

| Método | Ruta | Función | Controles OWASP |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Verificación de estado y versión del servicio. | Sin fuga de rutas internas ni credenciales. |
| `GET` | `/api/v1/stats` | Métricas agregadas del buzón (totales, limpios, sospechosos, cuarentena, URLs maliciosas). | Lectura inmutable sobre SQLite WAL. |
| `GET` | `/api/v1/emails?limit=50` | Listado de correos analizados recientes. | Paginación acotada estrictamente en `[1, 200]`. |
| `GET` | `/api/v1/emails/{email_id}/urls` | Desglose por capa de los enlaces de un correo específico. | Validación de entero positivo y entrega de `defanged_url`. |
| `POST` | `/api/v1/analyze` | Analizador manual de URLs al instante. | Validación funcional estricta de tipos y longitudes (`url <= 2048`, `subject <= 500`, `body <= 5000`), anti-XSS y neutralización visual (*defanging*). |

---

## 3. Controles de Seguridad Integrados en `app/main.py`

1. **Cabeceras Defensivas Globales (OWASP ASVS):** Middleware funcional que inyecta `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy` y `Cache-Control: no-store` en el 100% de las respuestas.
2. **Ocultamiento de Trazas Internas (OWASP A05):** Manejador global de excepciones no controladas que registra el fallo sanitizado en servidor y responde al cliente únicamente un `500` genérico sin exponer *stack traces* ni rutas de Debian.
3. **Concurrencia Segura (`lifespan` + `asyncio.to_thread`):** El monitor IMAP bloqueante corre en un hilo de trabajo separado gestionado por el ciclo de vida de FastAPI, evitando congelar el *event loop* de la API y garantizando apagado limpio (*graceful shutdown*).
