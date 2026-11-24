# 📘 Etapa 1: Configuración Segura, Tipos Inmutables y Persistencia Funcional

Este documento respalda técnicamente el desarrollo de la **Etapa 1**, alineando nuestra arquitectura **Functional Core, Imperative Shell** y los controles **OWASP ASVS** con el tablero de tareas del equipo (Trello).

---

## 1. Matriz de Trazabilidad Completa (Trello $\leftrightarrow$ Arquitectura Funcional)

Para mantener total cohesión con la planificación grupal, las 9 tarjetas propuestas en Trello se mapean de forma exacta con nuestras etapas de ingeniería:

| Tarjeta Trello | Nombre de la Tarea | Etapa | Archivos que la implementan |
| :--- | :--- | :---: | :--- |
| **Tarjeta #1** | Configuración inicial y credenciales | **Etapa 1** | `requirements.txt`, `.env.example`, `app/core/config.py`, `app/core/security.py`, `app/core/types.py` |
| **Tarjeta #2** | Diseño y carga de la Base de Datos (SQLite) | **Etapa 1 / 3** | `app/db/database.py` (esquema + whitelist) y `scripts/update_feeds.py` (carga URLhaus) |
| **Tarjeta #3** | Monitor de correos (IMAP) y extractor de URLs | **Etapa 2 / 3** | `app/services/parser_service.py` y `app/services/imap_service.py` |
| **Tarjeta #4** | Motor de detección híbrido | **Etapa 2 / 3** | `app/services/detection/{local_layer.py, vt_layer.py, heuristic_layer.py, engine.py}` |
| **Tarjeta #5** | Acción de Cuarentena y registro | **Etapa 3** | `app/services/imap_service.py` + persistencia en `app/db/database.py` |
| **Tarjeta #6** | Backend del Dashboard Web | **Etapa 4** | `app/api/routes.py` y `app/main.py` |
| **Tarjeta #7** | Interfaz gráfica del Dashboard (Frontend) | **Etapa 4** | `app/frontend/templates/index.html` y `app/frontend/static/styles.css` |
| **Tarjeta #8** | Pruebas integrales y simulación de ataque | **Transversal** | `tests/test_*.py` (ejecutados en cada etapa contra `docs/catalogo_edge_cases.md`) |
| **Tarjeta #9** | Preparación de la entrega y demo | **Cierre** | `README.md`, `docs/` y guía de demostración controlada |

---

## 2. Decisiones de Paradigma Funcional en la Etapa 1

1. **Cero Clases con Estado Mutable (Adiós POO / ORM):**
   Se descartó el uso de `SQLModel`/`SQLAlchemy` para evitar objetos acoplados a sesiones mutables. En su lugar, `app/core/types.py` define **estructuras de datos 100% inmutables** mediante `collections.namedtuple` (registros algebraicos ligeros en memoria cuyas propiedades no pueden reasignarse jamás en tiempo de ejecución).
2. **Carga Funcional de Secretos sin Exposición (`CWE-200`):**
   En `app/core/config.py`, las credenciales sensibles (`EMAIL_PASSWORD` y `VIRUSTOTAL_API_KEY`) se encapsulan en **clausuras léxicas (*closures*)** (`Callable[[], str]`). Si el registro `AppConfig` se imprime accidentalmente en consola, logs o trazas de excepción, Python muestra únicamente `<function _make_secret.<locals>.reveal ...>` en lugar de la contraseña en texto plano.
3. **Persistencia Funcional Parametrizada (`sqlite3` + `WAL`):**
   `app/db/database.py` opera exclusivamente mediante funciones puras de borde que reciben la ruta de la base de datos (o una conexión abierta), ejecutan sentencias SQL parametrizadas con marcadores `?` (mitigando al 100% **CWE-89 SQL Injection**) y transforman las filas crudas en tuplas `namedtuple` inmutables antes de retornarlas.

---

## 3. Especificación de Archivos Desarrollados en esta Etapa

### 3.1 `app/core/types.py`
Contiene el vocabulario de datos inmutables compartido por todo el sistema:
* `SecretGetter`: Alias funcional `Callable[[], str]` para proteger secretos en memoria.
* `AppConfig`: Tupla inmutable con todos los parámetros operativos, límites anti-DoS y listas contextuales del sector aduanero de Chacao (tuplas inmutables `tuple[str, ...]`, nunca listas mutables `list`).
* `ExtractedLink`, `ParsedEmail`, `UrlAnalysisRecord`, `EmailRecord`, `DashboardStats`: Contratos de datos inmutables entre el parser, el motor, SQLite y la API.

### 3.2 `app/core/config.py`
* `build_config_from_mapping(env_map)`: Función pura cuando se le inyecta un diccionario `Mapping[str, str]` (ideal para tests deterministas) que valida rangos numéricos estrictos (puertos $1\text{–}65535$, intervalos mínimos, topes de bytes) y normaliza dominios y palabras clave en tuplas inmutables.

### 3.3 `app/core/security.py`
* `sanitize_for_log(value, max_len)`: Función pura que reemplaza `\r`, `\n`, `\t` y caracteres de control ASCII ($< 32$ o $127$) por espacios simples, neutralizando ataques de **Log Injection (`CWE-117` / `EC-WEB-03`)**.
* `defang_url(url)`: Función pura que neutraliza visualmente enlaces maliciosos (`http://` $\rightarrow$ `hxxp://`, `.` $\rightarrow$ `[.]`, `javascript:` $\rightarrow$ `blocked-js:`) para mostrarlos de forma segura en el Dashboard sin riesgo de clic accidental.
* `get_owasp_security_headers()`: Retorna un diccionario inmutable de cabeceras HTTP **OWASP ASVS** (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`).

### 3.4 `app/db/database.py`
* `open_db_connection(db_path)`: Abre conexión `sqlite3` aplicando `PRAGMA journal_mode=WAL`, `PRAGMA foreign_keys=ON` y `PRAGMA busy_timeout=5000` (mitigando `EC-EXT-04`).
* `init_database(db_path)`: Crea de forma idempotente las 4 tablas relacionales (`processed_emails`, `analyzed_urls`, `threat_feeds`, `whitelisted_domains`), sus índices y precarga la lista blanca logística/institucional.
* Funciones de consulta y escritura atómica: `is_email_already_processed`, `fetch_whitelisted_domains`, `is_url_or_domain_blacklisted`, `insert_threat_feed_batch`, `save_email_analysis`, `get_dashboard_stats` y `list_recent_emails`.

---

## 4. Verificación y Cobertura de Casos Borde (`tests/test_etapa1_core_db.py`)

La suite automatizada verifica:
1. **Inmutabilidad estricta:** Intento de mutación sobre `AppConfig` y `EmailRecord` (`AttributeError` garantizado).
2. **Ocultamiento de secretos (`ACT-01`):** Verificación de que `repr(config)` y `str(config)` jamás filtran contraseñas ni API keys.
3. **Neutralización de Log Injection (`EC-WEB-03`):** Eliminación de secuencias `\r\n` y bytes nulos `\x00`.
4. **Neutralización de SQL Injection (`EC-WEB-02`):** Inserción y búsqueda con payloads `'; DROP TABLE processed_emails;--` verificando integridad intacta del esquema.
5. **Idempotencia por `message_id` y concurrencia `WAL` (`EC-EXT-04`).**