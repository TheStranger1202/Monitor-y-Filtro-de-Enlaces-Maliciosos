# Documentación Técnica — Etapa 2: Extractor MIME/HTML y Capas Puras de Detección (1 y 3)

Este documento respalda el diseño e implementación funcional (100% libre de POO) del **Extractor Seguro de Enlaces** y de las **Capas 1 y 3 del Motor Híbrido**, cubriendo las **Tarjetas #3 (parcial) y #4 de Trello**.

---

## 1. Trazabilidad con el Tablero del Equipo (Trello)

| Tarjeta de Trello | Módulos Implementados | Estado |
| :--- | :--- | :--- |
| **3. Monitor de correos y extractor de URLs** *(Submódulo Extractor MIME/HTML)* | `app/services/parser_service.py` | Completado y probado |
| **4. Motor de detección híbrido** *(Capa 1 Local + Capa 3 Heurística Aduanera)* | `app/services/detection/local_layer.py`, `app/services/detection/heuristic_layer.py` | Completado y probado |

---

## 2. Responsabilidad Funcional y Controles OWASP por Archivo

### 2.1 `app/services/parser_service.py` (Núcleo Puro de Extracción)
* **Anti-DoS por Tamaño (`EC-MIME-04`):** Trunca cualquier flujo crudo mayor a `max_email_bytes` antes de parsear la estructura MIME.
* **Tolerancia a Codificaciones Corruptas (`EC-MIME-01`, `EC-MIME-02`):** Decodifica cabeceras RFC 2047 y cuerpos con `errors="replace"` y genera un hash SHA-256 determinista si el correo carece de `Message-ID`.
* **Extracción Dual (DOM HTML + Texto Plano — `EC-MIME-03`):** Extrae pares `(href, texto_visible)` desde etiquetas `<a>` usando `BeautifulSoup` y captura URLs sueltas en texto plano con una expresión regular lineal libre de *backtracking* catastrófico (**anti-ReDoS / CWE-1333 / `EC-URL-08`**).
* **Normalización Punycode (`idna` — `EC-URL-01`):** Convierte dominios Unicode internacionalizados a su representación ASCII `xn--...` para impedir evasión visual con alfabetos cirílicos o griegos.
* **Deduplicación Acotada (`EC-MIME-05`):** Elimina enlaces repetidos conservando el orden y limita la salida a `max_urls_per_email`.

### 2.2 `app/services/detection/local_layer.py` (Capa 1: Control Local)
* **Validación Estricta de Subdominios (`EC-URL-05`):** Un dominio coincide con la Lista Blanca **únicamente** si es idéntico (`domain == trusted`) o termina exactamente en `"." + trusted`. Esto bloquea por completo ataques como `maersk.com.evil.ru` o `fakemaersk.com`.
* **Prioridad Defensiva:** Si una URL específica o su dominio figura en la lista negra local (`threat_feeds`), devuelve `BLACKLISTED` inmediatamente incluso antes de evaluar reglas secundarias.

### 2.3 `app/services/detection/heuristic_layer.py` (Capa 3: Contexto Aduanero Chacao)
Implementa una suma funcional inmutable acotada en $[0, 100]$ que evalúa:
1. **Esquemas Peligrosos (`+100` — `EC-XSS-02`):** `javascript:`, `data:`, `vbscript:`, `file:`.
2. **Credenciales Embebidas en URL (`+65` — `EC-URL-02`):** Uso de `usuario@host` (`https://seniat.gob.ve@evil.com`).
3. **IP Directa o Privada/Loopback (`+45` / `+75` — `EC-URL-03`, `EC-URL-04`):** Uso de IPv4/IPv6 sin dominio o direcciones internas RFC 1918 / `127.0.0.1` (anti-SSRF / phishing interno).
4. **Homógrafos IDN / Punycode (`+45` — `EC-URL-01`):** Presencia de prefijos `xn--` en etiquetas de dominio.
5. **Typosquatting Logístico/Aduanero (`+55`):** Distancia de edición (Levenshtein vía `rapidfuzz`) entre $1$ y $2$ respecto a dominios protegidos (`maersk.com`, `dhl.com`, `seniat.gob.ve`, `bolipuertos.gob.ve`, etc.) o inclusión engañosa de la marca en dominios externos (`dhl-envios-chacao.com`).
6. **Discrepancia `href` vs Texto Visible (`+50` — `EC-URL-06`):** Cuando el texto visible del hipervínculo aparenta ser un dominio distinto al dominio real de destino.
7. **Puertos No Estándar (`+25` — `EC-URL-07`):** Puertos distintos de `80` y `443`.
8. **Acortadores de URL (`+20`) y Jerga Aduanera de Ingeniería Social (`+15`):** Términos como *"guía retenida"*, *"manifiesto de carga"*, *"pago de aranceles"*, *"liberación de contenedor"*.
