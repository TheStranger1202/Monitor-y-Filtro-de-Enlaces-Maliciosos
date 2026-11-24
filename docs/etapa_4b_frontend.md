# Documentación Técnica — Etapa 4B: Interfaz Gráfica SOC (Frontend Seguro y Funcional)

Este documento respalda la implementación de la interfaz web del sistema bajo la identidad visual **Dark Gothic-Cyberpunk SOC**, completando la **Tarjeta #7 de Trello**.

---

## 1. Trazabilidad con el Tablero del Equipo (Trello)

| Tarjeta de Trello | Módulos Implementados | Estado |
| :--- | :--- | :--- |
| **7. Interfaz gráfica del Dashboard (Frontend)** | `app/frontend/templates/index.html`, `app/frontend/static/styles.css`, `app/frontend/static/app.js`, `app/main.py`, `app/core/security.py`, `tests/test_etapa4b_frontend.py` | Completado y probado |

---

## 2. Arquitectura UX y Ergonomía Visual

1. **Navegación Modular por Vistas (App Shell con Sidebar):**
   * Evita la saturación cognitiva separando la operación en tres vistas dedicadas:
     * **Panel de Mando:** Indicadores clave de rendimiento (KPI) y estado del demonio IMAP en tiempo real.
     * **Bitácora Forense:** Filtrado por veredicto (`QUARANTINED`, `SUSPICIOUS`, `CLEAN`), búsqueda local instantánea y **Drawer Lateral de Autopsia** para inspeccionar enlaces sin perder la tabla de contexto.
     * **Oráculo de URLs:** Consola aislada para análisis manual inmediato contra las 3 capas.
2. **Confort Visual (Dark Mode Calibrado):**
   * Base en tono pizarra abisal (`#0b0d12`) y superficies elevadas (`#121620`) con contraste WCAG AA+ (`#e2e8f0`) para evitar deslumbramiento y fatiga ocular, acentuado con carmesí táctico (`#e11d48`), esmeralda terminal (`#10b981`) y violeta arcano (`#8b5cf6`).
3. **Identidad Open-Source:**
   * Sigilo vectorial SVG propio y identidad visual del proyecto integrados en la interfaz para distribución pública bajo licencia MIT.

---

## 3. Controles de Seguridad OWASP (Threat Modeling Aplicado)

* **Inmunidad contra Blind Stored XSS (`EC-XSS-01` / CWE-79):** `app/frontend/static/app.js` está escrito en estilo **100% funcional (cero clases `class`)** y prohíbe el uso de `innerHTML` o `insertAdjacentHTML`. Todos los asuntos, remitentes, dominios y URLs desarmadas (`defanged_url`) se insertan mediante `document.createTextNode` / `.textContent`.
* **Content-Security-Policy (CSP) Sin Excepciones `unsafe-inline`:** Al alojar estilos y scripts exclusivamente en `/static/styles.css` y `/static/app.js`, se endurece `style-src 'self'` y `script-src 'self'` en `app/core/security.py`, eliminando cualquier vector de inyección CSS/JS en línea y permitiendo operación 100% *offline*.
