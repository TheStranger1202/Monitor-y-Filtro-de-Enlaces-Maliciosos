# 🗺️ Mapa Funcional y Especificación de Seguridad por Archivo (`.py`)

Este documento detalla la responsabilidad arquitectónica, las entradas/salidas, los controles de codificación segura (OWASP ASVS / Top 10) y el archivo de pruebas asociado para cada módulo Python del proyecto antes de su implementación.

---

## 1. Núcleo y Seguridad Transversal (`app/core/`)

### 1.1 `app/core/config.py`
* **Función:** Centraliza la carga tipada de variables de entorno desde `.env`, define los umbrales matemáticos de riesgo ($30$ y $60\text{ puntos}$), límites anti-DoS y las listas de contexto aduanero/logístico del municipio Chacao.
* **Controles de Seguridad:**
  * Uso de clausuras léxicas (`make_secret`) para `EMAIL_PASSWORD` y `VIRUSTOTAL_API_KEY`, impidiendo su exposición accidental en `print()`, logs o trazas de excepción (mitiga **CWE-200**).
  * Validación estricta de rangos numéricos (`ge`, `le`) para puertos, intervalos de tiempo y límites de tamaño de correo/URL.
* **Test asociado:** `tests/test_etapa1_core_db.py`

### 1.2 `app/core/security.py`
* **Función:** Provee utilidades transversales de ciberseguridad para todo el sistema: sanitización de cadenas para logs, enmascaramiento visual de enlaces peligrosos (*defanging*, ej. `hxxp://`) y middleware HTTP con cabeceras de seguridad para FastAPI.
* **Controles de Seguridad:**
  * Eliminación de secuencias CRLF (`\r`, `\n`) y caracteres de control ASCII en registros de auditoría (mitiga **CWE-117 Log Injection**).
  * Inyección automática de cabeceras OWASP en cada respuesta HTTP: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` y `Referrer-Policy: no-referrer` (mitiga **CWE-79 XSS** y **Clickjacking**).
* **Test asociado:** `tests/test_etapa1_core_db.py`

---

## 2. Capa de Persistencia (`app/db/`)

### 2.1 `app/core/types.py`
* **Función:** Define los registros inmutables con `collections.namedtuple` (cero clases POO): `AppConfig`, `ParsedEmail`, `ExtractedLink`, `UrlVerdict`, `EmailRecord` y `DashboardStats`.
* **Controles de Seguridad:**
  * Restricciones explícitas `max_length` en todos los campos de texto para evitar desbordamientos lógicos y almacenamiento abusivo.
  * Índices únicos (`unique=True`) en `message_id`, `url` y `domain` para garantizar idempotencia e integridad referencial.
  * Fechas estandarizadas en UTC (`datetime.now(timezone.utc)`).
* **Test asociado:** `tests/test_etapa1_core_db.py`

### 2.2 `app/db/database.py`
* **Función:** Inicializa el motor SQLite, configura pragmas de rendimiento/concurrencia, gestiona transacciones por sesión y precarga de forma idempotente los dominios verificados en `WhitelistedDomain`.
* **Controles de Seguridad:**
  * Activación automática de `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL` y `PRAGMA foreign_keys=ON` al conectar, previniendo bloqueos concurrentes (`database is locked`).
  * Consultas 100% parametrizadas sobre `sqlite3` nativo (mitiga **CWE-89 SQL Injection**).
* **Test asociado:** `tests/test_etapa1_core_db.py`

---

## 3. Extracción y Motor de Detección en 3 Capas (`app/services/`)

### 3.1 `app/services/parser_service.py`
* **Función:** Recibe los bytes crudos de un correo RFC 5322, extrae de forma segura metadatos (`Message-ID`, `From`, `Subject`), decodifica partes `text/plain` y `text/html`, analiza el DOM con `BeautifulSoup` y devuelve enlaces normalizados junto con su texto visible.
* **Controles de Seguridad:**
  * Tope estricto de bytes procesados por correo y límite máximo de URLs extraídas (mitiga **CWE-400 Resource Exhaustion**).
  * Expresiones regulares lineales libres de cuantificadores anidados ambiguos (mitiga **CWE-1333 ReDoS**).
  * Conversión de dominios internacionalizados a **Punycode (`idna`)**, detección de credenciales embebidas (`usuario@host`) y captura explícita de esquemas peligrosos (`javascript:`, `data:`, `vbscript:`).
* **Test asociado:** `tests/test_etapa2_parser_heuristics.py`

### 3.2 `app/services/detection/local_layer.py`
* **Función:** Ejecuta la **Capa 1** del motor híbrido consultando en milisegundos si el dominio pertenece a la lista blanca institucional o si la URL/dominio figura en la tabla local `ThreatFeed`.
* **Controles de Seguridad:**
  * Algoritmo estricto de coincidencia jerárquica de dominios: un dominio solo coincide con `maersk.com` si es exactamente `maersk.com` o termina en `.maersk.com`, bloqueando evasiones como `fakemaersk.com` o `maersk.com.attacker.com`.
* **Test asociado:** `tests/test_etapa2_parser_heuristics.py`

### 3.3 `app/services/detection/vt_layer.py`
* **Función:** Ejecuta la **Capa 2** consultando la reputación del enlace en la API v3 de VirusTotal (`/api/v3/urls/{url_id}`) codificando la URL en Base64 URL-safe sin relleno (*padding*).
* **Controles de Seguridad:**
  * **Prevención absoluta de SSRF (CWE-918):** Jamás conecta con el enlace sospechoso; únicamente establece conexión TLS verificada hacia `https://www.virustotal.com`.
  * Controlador de tasa (*Rate Limiter*) integrado para no superar las $4\text{ peticiones/minuto}$, caché en memoria de resultados recientes y manejo resiliente (*fail-safe*) ante errores `429`, `404`, `5xx` o *timeouts*.
* **Test asociado:** `tests/test_etapa2_parser_heuristics.py`

### 3.4 `app/services/detection/heuristic_layer.py`
* **Función:** Ejecuta la **Capa 3** evaluando anomalías estructurales y contextuales del sector de importación y exportación en Chacao (distancia de Levenshtein con `rapidfuzz` contra navieras/aduanas, homógrafos Punycode `xn--`, IPs literales, discrepancia entre texto visible y `href`, acortadores, puertos inusuales y palabras clave aduaneras).
* **Controles de Seguridad:**
  * Operaciones puramente determinísticas en memoria local en tiempo acotado ($O(n)$), inmunes a caídas de internet o evasiones de firmas tradicionales.
* **Test asociado:** `tests/test_etapa2_parser_heuristics.py`

### 3.5 `app/services/detection/engine.py`
* **Función:** Orquesta secuencialmente las Capas 1, 2 y 3 para todas las URLs únicas de un correo, calcula el puntaje acotado en $[0, 100]$ según la ecuación del modelo teórico y emite el veredicto consolidado (`CLEAN`, `SUSPICIOUS` o `QUARANTINED`).
* **Controles de Seguridad:**
  * Cortocircuito inmediato en Capa 1 (ahorro de API en listas blancas y bloqueo instantáneo en listas negras).
  * Límite máximo de consultas externas a VirusTotal por correo para impedir ataques de agotamiento de cuota (*Quota Exhaustion*).
* **Test asociado:** `tests/test_etapa3_engine_imap_feeds.py`

### 3.6 `app/services/imap_service.py`
* **Función:** Gestiona la conexión `IMAP4_SSL` hacia el buzón institucional, verifica periódicamente mensajes no registrados en SQLite, coordina su análisis con el motor y traslada automáticamente a la carpeta `Cuarentena` aquellos con puntaje $\ge 60$.
* **Controles de Seguridad:**
  * Contexto criptográfico estricto (`ssl.create_default_context()`) que exige validación de certificado y nombre de host TLS.
  * Uso de comandos IMAP basados en **UID** (`uid('COPY', ...)`, `uid('STORE', ...)`) previa validación numérica estricta para prevenir condiciones de carrera e **IMAP Injection (CWE-93)**.
* **Test asociado:** `tests/test_etapa3_engine_imap_feeds.py`

---

## 4. Utilidades, API Web y Punto de Entrada

### 4.1 `scripts/update_feeds.py`
* **Función:** Descarga de forma segura el listado público de URLs maliciosas activas (URLhaus), valida cada entrada e inserta lotes actualizados en `ThreatFeed`.
* **Controles de Seguridad:**
  * Descarga por *streaming* con corte inmediato si el tamaño excede el límite configurado (anti *Stream Bomb*) y validación sintáctica antes de persistir en SQLite.
* **Test asociado:** `tests/test_etapa3_engine_imap_feeds.py`

### 4.2 `app/api/routes.py`
* **Función:** Define las rutas HTTP de FastAPI para servir el Dashboard, consultar métricas agregadas, listar alertas recientes y analizar enlaces manualmente bajo demanda.
* **Controles de Seguridad:**
  * Validación de entrada mediante funciones puras de validación estricta, límites de paginación (`limit <= 100`) y entrega de URLs neutralizadas para evitar clics accidentales del administrador en el panel.
* **Test asociado:** `tests/test_etapa4a_api_backend.py`

### 4.3 `app/main.py`
* **Función:** Instancia la aplicación FastAPI, registra el middleware de cabeceras OWASP, inicializa SQLite y administra de forma limpia el arranque y parada (*graceful shutdown*) de la tarea en segundo plano del monitor IMAP mediante `lifespan`.
* **Controles de Seguridad:**
  * Manejador global de excepciones que registra el error internamente de forma sanitizada y devuelve un mensaje genérico seguro al cliente HTTP sin filtrar rutas ni variables internas.
* **Test asociado:** `tests/test_etapa4a_api_backend.py`

---

## 5. Plan de Ejecución por Etapas Controladas

Una vez aprobada esta documentación en el repositorio, el desarrollo y verificación con `pytest` se ejecutará estrictamente en cinco etapas secuenciales:

1. **Etapa 1 — Base Segura y Persistencia:** `requirements.txt`, `app/core/config.py`, `app/core/security.py`, `app/core/types.py`, `app/db/database.py` + pruebas `test_etapa1_core_db.py` y `test_etapa1_core_db.py`.
2. **Etapa 2 — Extracción Segura MIME/HTML:** `app/services/parser_service.py` + pruebas `test_etapa2_parser_heuristics.py` (cubriendo `EC-URL-*` y `EC-MIME-*`).
3. **Etapa 3 — Motor de Detección en 3 Capas:** `local_layer.py`, `vt_layer.py`, `heuristic_layer.py` y `engine.py` + pruebas `test_etapa2_parser_heuristics.py` y `test_etapa3_engine_imap_feeds.py`.
4. **Etapa 4 — Monitor IMAP y Actualizador de Feeds:** `app/services/imap_service.py` y `scripts/update_feeds.py` + pruebas con mocks `test_etapa3_engine_imap_feeds.py` y `test_etapa3_engine_imap_feeds.py`.
5. **Etapa 5 — API REST, Dashboard Web e Integración Final:** `app/api/routes.py`, `app/main.py` y plantillas HTML seguras + pruebas `test_etapa4a_api_backend.py` (cubriendo `EC-WEB-*`).