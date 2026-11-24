# Documentación Técnica — Etapa 3: Capa 2 (VirusTotal), Orquestador Híbrido, Monitor IMAP y Feeds

Este documento respalda la implementación funcional (100% libre de POO) de las integraciones externas controladas (*Imperative Shell*) y el orquestador matemático (*Functional Core*), completando las **Tarjetas #3, #4 y #5 de Trello**.

---

## 1. Trazabilidad con el Tablero del Equipo (Trello)

| Tarjeta de Trello | Módulos Implementados | Estado |
| :--- | :--- | :--- |
| **2. Carga de Base de Datos (Feeds URLhaus)** | `scripts/update_feeds.py` | Completado y probado |
| **3. Monitor de correos (IMAP)** | `app/services/imap_service.py` | Completado y probado |
| **4. Motor de detección híbrido (Capa 2 + Orquestador)** | `app/services/detection/vt_layer.py`, `app/services/detection/engine.py` | Completado y probado |
| **5. Acción de Cuarentena y registro** | `app/services/imap_service.py` (`quarantine_message_by_uid`) | Completado y probado |

---

## 2. Responsabilidad Funcional y Controles de Seguridad (OWASP)

### 2.1 `app/services/detection/vt_layer.py` (Capa 2: VirusTotal API v3)
* **Anti-SSRF Absoluto (OWASP A10):** El sistema **jamás realiza peticiones HTTP hacia la URL sospechosa**. Codifica la cadena en Base64 URL-safe sin relleno (`=`) según la especificación oficial de VirusTotal v3 (`GET https://www.virustotal.com/api/v3/urls/{id}`) con verificación TLS obligatoria (`verify=True`).
* **Control de Tasa Funcional (`make_rate_limiter`):** Clausura léxica sin clases que garantiza el espaciado mínimo (`vt_rate_limit_seconds = 16s`) para respetar las 4 peticiones/minuto de la capa gratuita.
* **Degradación Elegante (`EC-EXT-01`, `EC-EXT-02`, `EC-EXT-03`):** Ante códigos `404` (URL nueva no indexada), `429` (cuota excedida), `5xx`, *timeouts* de red o JSON malformado, nunca lanza excepciones no controladas; devuelve un `VtLayerResult(0, 0, error=...)` permitiendo que las Capas 1 y 3 decidan sin detener la protección.

### 2.2 `app/services/detection/engine.py` (Orquestador Matemático de 3 Capas)
* **Inyección Funcional de Efectos (Higher-Order Functions):** `evaluate_single_link` y `evaluate_parsed_email` reciben funciones (`is_blacklisted_fn`, `vt_Lookup_fn`) como parámetros explícitos, separando la matemática pura del I/O.
* **Cortocircuito Inteligente y Protección de Cuota:**
  1. Si Capa 1 devuelve `BLACKLISTED` $\rightarrow$ Puntaje directo `100` (`MALICIOUS`), cero gasto de API externa.
  2. Si Capa 1 devuelve `WHITELISTED` y no hay engaño visual (`anchor_text_domain_mismatch`) ni credenciales embebidas $\rightarrow$ Puntaje `0` (`SAFE`), cero gasto de API externa.
  3. Límite estricto `max_vt_queries_per_email = 4` para impedir que un correo con decenas de enlaces desconocidos congele el monitor o agote la llave de API.
* **Fórmula Ponderada Acotada $[0, 100]$:**
  $$S_{\text{VT}} = \min(100,\; 35 \cdot M_{\text{VT}} + 15 \cdot S_{\text{susp}})$$
  $$S_{\text{final}} = \min(100,\; S_{\text{VT}} + S_{\text{heurística}})$$

### 2.3 `app/services/imap_service.py` (Monitor IMAP TLS y Cuarentena)
* **Prevención de IMAP Command Injection (`EC-IMAP-01` / CWE-93):** Validación estricta mediante expresión regular numérica `^[0-9]+$` para UIDs y sanitización de nombres de carpeta rechazando comillas, barras invertidas y caracteres de control CRLF.
* **TLS Estricto:** Conexión exclusiva mediante `imaplib.IMAP4_SSL` con `ssl.create_default_context()` (rechaza certificados autofirmados o caducados).
* **Cuarentena Atómica Segura (`EC-IMAP-02`):** Verifica/crea la carpeta `Cuarentena` antes de ejecutar `UID COPY` + marcado `\Deleted` + `EXPUNGE` únicamente si la copia al buzón de aislamiento respondió `OK` (garantizando cero pérdida de correos).

### 2.4 `scripts/update_feeds.py` (Ingesta Segura de Inteligencia URLhaus)
* **Anti-Stream Bomb (`EC-EXT-04`):** Descarga en *streaming* por fragmentos (`iter_bytes`) abortando inmediatamente si el flujo supera `max_bytes` (por defecto 15 MB) y exigiendo esquema `https://`.
