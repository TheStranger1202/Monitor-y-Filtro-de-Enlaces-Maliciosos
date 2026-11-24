# PhishGuard-Chacao — Monitor y Filtro de Enlaces Maliciosos (ICES)

Sistema preventivo de **Seguridad Integrada de Correo Electrónico en la Nube (ICES)** diseñado para empresas de importación, exportación y logística aduanera en el municipio Chacao (Caracas, Venezuela).

Monitorea buzones corporativos vía **IMAP TLS**, extrae y normaliza enlaces de correos MIME/HTML, los evalúa mediante un **Motor de Detección Híbrido de 3 Capas** y aísla automáticamente los mensajes maliciosos en una carpeta `Cuarentena`, ofreciendo una consola SOC web para auditoría forense y análisis manual bajo demanda.

---

## Arquitectura y Principios de Ingeniería

* **Paradigma 100% Funcional (*Functional Core, Imperative Shell*):** Cero clases POO en Python y JavaScript (auditado automáticamente mediante el árbol de sintaxis abstracta `ast` en la suite de pruebas). Estructuras de datos inmutables (`namedtuple`, `frozenset`, `tuple`) y protección de secretos mediante clausuras léxicas (*closures*) que impiden fugas en logs o *tracebacks*.
* **Seguridad por Diseño (OWASP Top 10 / ASVS / STRIDE):**
  * **Anti-SSRF:** El sistema jamás visita ni resuelve HTTP hacia URLs sospechosas; consulta reputación externa mediante el identificador Base64 URL-safe en VirusTotal v3.
  * **Anti-XSS (*Blind Stored XSS*):** Interfaz SOC con `Content-Security-Policy` estricto (`script-src 'self'`, `style-src 'self'`, cero `unsafe-inline`) y construcción DOM pura sin `innerHTML`. Todas las URLs se neutralizan visualmente (*defanging*: `hxxps://...[.]...`).
  * **Anti-SQLi y Concurrencia:** `sqlite3` nativo en modo `WAL` con claves foráneas activas y consultas 100% parametrizadas.
  * **Anti-ReDoS, Anti-IMAP Injection y Anti-Log Injection:** Expresiones regulares lineales, validación estricta de UIDs/carpetas IMAP, límites de tamaño MIME/URL y sanitización CRLF.

---

## Motor de Detección Híbrido (3 Capas)

1. **Capa 1 — Control Local (SQLite WAL):** Validación estricta de sufijos contra Lista Blanca corporativa (navieras, couriers y entes aduaneros) y Lista Negra local sincronizada desde **OpenPhish** (con soporte dual automático para feeds CSV tipo URLhaus).
2. **Capa 2 — Inteligencia Externa (VirusTotal API v3):** Consulta reputacional con *rate limiter* funcional integrado y degradación elegante ante límites `429`, *timeouts* o ausencia de API Key.
3. **Capa 3 — Heurística Aduanera:** Detección de homógrafos IDN/Punycode (`xn--`), *typosquatting* y *brand-impersonation* (distancia de Levenshtein vía `rapidfuzz`) contra navieras y entes (`maersk.com`, `dhl.com`, `seniat.gob.ve`, `bolipuertos.gob.ve`), credenciales embebidas (`user@host`), IPs directas/privadas, puertos no estándar, discrepancia `href` vs texto visible y señuelos de ingeniería social aduanera.

---

## Estructura del Repositorio

```text
phishguard-chacao/
├── app/
│   ├── api/routes.py                  # Endpoints REST (/api/v1/*)
│   ├── core/
│   │   ├── config.py                  # Carga funcional e inmutable de configuración
│   │   ├── security.py                # Sanitización de logs, defanging y cabeceras OWASP
│   │   └── types.py                   # Registros inmutables (namedtuple) y clausuras
│   ├── db/database.py                 # Persistencia funcional SQLite WAL parametrizada
│   ├── frontend/
│   │   ├── templates/index.html       # Consola SOC (Panel de Mando, Bitácora, Oráculo)
│   │   └── static/{styles.css,app.js} # Estilos y controlador funcional anti-XSS
│   ├── services/
│   │   ├── detection/
│   │   │   ├── local_layer.py         # Capa 1: Lista Blanca y Lista Negra local
│   │   │   ├── vt_layer.py            # Capa 2: VirusTotal v3 + Rate Limiter
│   │   │   ├── heuristic_layer.py     # Capa 3: Heurística aduanera y homógrafos
│   │   │   └── engine.py              # Orquestador híbrido con cortocircuitos
│   │   ├── imap_service.py            # Monitor IMAP TLS y acción de Cuarentena
│   │   └── parser_service.py          # Extractor MIME/HTML seguro anti-ReDoS
│   └── main.py                        # Punto de entrada FastAPI y ciclo de vida
├── docs/                              # Documentación técnica por etapa y trazabilidad
├── scripts/update_feeds.py            # Sincronizador seguro de feeds (OpenPhish / CSV)
├── tests/                             # Suite automatizada pytest (23 pruebas)
├── .env.example                       # Plantilla de variables de entorno
├── pytest.ini                         # Configuración de entorno de pruebas
└── requirements.txt                   # Dependencias del proyecto
```

---

## Instalación y Uso Rápido

### 1. Clonar y preparar el entorno virtual (Python 3.13+)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configurar variables de entorno
```bash
cp .env.example .env
chmod 600 .env
```
Edita `.env` con:
* `VIRUSTOTAL_API_KEY`: Tu clave gratuita de VirusTotal v3 (opcional; si se omite, el sistema opera con las Capas 1 y 3).
* `EMAIL_USER` y `EMAIL_PASSWORD`: Cuenta IMAP y su **Contraseña de Aplicación** (si se dejan vacíos, el servidor inicia solo en modo Dashboard + Oráculo manual sin encender el demonio IMAP).

### 3. Sincronizar indicadores de amenazas (OpenPhish)
```bash
python3 -m scripts.update_feeds
```

### 4. Ejecutar el servidor y abrir la Consola SOC
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Accede a **`http://127.0.0.1:8000`** para utilizar el **Panel de Mando**, la **Bitácora Forense** y el **Oráculo de URLs**.

---

## Pruebas Automatizadas y Documentación

Ejecuta la suite completa de seguridad, auditoría AST (cero clases POO) y casos borde (23 pruebas):
```bash
pytest -v
```

La documentación técnica detallada de cada fase del desarrollo se encuentra en [`docs/`](docs/):
* `docs/etapa_1_nucleo_y_persistencia.md` — Configuración funcional, seguridad OWASP y SQLite WAL.
* `docs/etapa_2_parser_y_capas_puras.md` — Extractor MIME/HTML y Capas 1 y 3.
* `docs/etapa_3_motor_hibrido_imap_feeds.md` — Capa VirusTotal, orquestador, monitor IMAP y feeds.
* `docs/etapa_4a_api_backend.md` — API REST FastAPI y ciclo de vida.
* `docs/etapa_4b_frontend.md` — Interfaz SOC y endurecimiento CSP/XSS.

---

## Licencia

Distribuido bajo licencia MIT. Libre para uso, auditoría y mejora por la comunidad.