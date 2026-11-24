# Manual de Usuario — PhishGuard-Chacao (Consola SOC)

Guía práctica de operación para administradores de TI y analistas de seguridad de empresas de importación, exportación y logística aduanera que utilizan **PhishGuard-Chacao** para proteger su correo institucional.

---

## 1. ¿Qué hace el sistema por ti?

**PhishGuard-Chacao** vigila automáticamente tu bandeja de entrada (`INBOX`) a través de una conexión cifrada (**IMAP TLS**), extrae los enlaces de cada correo nuevo y los evalúa en segundos mediante tres niveles de defensa (listas locales, VirusTotal y heurística aduanera) **sin abrir ni visitar jamás el enlace sospechoso**.

Si un mensaje representa una amenaza alta, el sistema lo mueve de forma automática a una carpeta llamada **`Cuarentena`** dentro de tu propio buzón y registra la evidencia en la Consola Web para que puedas auditarla con total seguridad.

---

## 2. Preparación Inicial (Credenciales y Arranque)

### 2.1 Configurar la cuenta de correo (Contraseña de Aplicación)
Por seguridad, proveedores como Gmail u Outlook bloquean el uso de tu contraseña habitual en conexiones IMAP. Debes generar una **Contraseña de Aplicación**:
1. Activa la **Verificación en 2 pasos** en la configuración de seguridad de tu cuenta de correo.
2. Busca la opción **Contraseñas de aplicaciones**, crea una nueva llamada `PhishGuard` y copia la clave de 16 caracteres que genera.
3. Abre el archivo `.env` en la raíz del proyecto y completa:
   * `EMAIL_USER`: tu dirección de correo institucional.
   * `EMAIL_PASSWORD`: la contraseña de aplicación de 16 caracteres.
   * `VIRUSTOTAL_API_KEY`: tu clave gratuita de VirusTotal (opcional; si la dejas vacía, el sistema sigue protegiendo con las listas locales y la heurística aduanera).

> **Modo solo análisis manual:** Si dejas `EMAIL_USER` y `EMAIL_PASSWORD` vacíos, la Consola Web funcionará normalmente para consultar el historial y usar el **Oráculo de URLs**, sin activar el monitoreo automático del buzón.

### 2.2 Actualizar la base de amenazas y encender la Consola
Desde la terminal, con el entorno virtual activado (`source .venv/bin/activate`):

1. **Actualizar indicadores de phishing (OpenPhish):**
   ```bash
   python3 -m scripts.update_feeds
   ```
   *(Recomendado ejecutarlo una vez al día o antes de iniciar la jornada).*
2. **Iniciar el servidor:**
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
3. Abre tu navegador y entra a **`http://127.0.0.1:8000`**.

---

## 3. Guía de la Consola Web (Las 3 Vistas)

La barra lateral izquierda te permite cambiar instantáneamente entre tres módulos y consultar el estado del motor en la esquina inferior izquierda (**Núcleo Activo // TLS OK**). La consola se sincroniza automáticamente cada **15 segundos** (o al pulsar **Sincronizar**).

### Vista 1: Panel de Mando
Resumen ejecutivo en tiempo real de la salud de tu buzón:
* **Correos Analizados:** Total de mensajes procesados desde el inicio.
* **Aislados en Cuarentena:** Mensajes peligrosos movidos automáticamente fuera de `INBOX`.
* **Enlaces Maliciosos:** Cantidad total de URLs hostiles neutralizadas.
* **Tráfico Limpio:** Correos verificados sin riesgo.
* **Últimas Intercepciones:** Tabla rápida con los 6 mensajes más recientes. Haz clic en cualquier fila para abrir su autopsia forense.

### Vista 2: Bitácora Forense
Historial completo de correos auditados con herramientas de investigación:
* **Filtros rápidos:** Filtra con un clic entre *Todos*, *Cuarentena*, *Sospechosos* y *Limpios*.
* **Buscador instantáneo:** Escribe parte del remitente o del asunto para localizar un incidente específico.
* **Drawer de Autopsia:** Al hacer clic en cualquier fila (o en el botón **Autopsia**), se despliega un panel lateral derecho con el `Message-ID`, el remitente y el desglose individual de cada enlace que contenía el correo (capa activada, detecciones de VirusTotal y reglas heurísticas disparadas). Pulsa `Esc` o el botón de cierre para ocultarlo.

### Vista 3: Oráculo de URLs (Analizador Manual)
Úsalo cuando un empleado te reenvíe un enlace dudoso por WhatsApp, chat o correo y quieras verificarlo antes de hacer clic:
1. Pega el enlace en **URL Objetivo**.
2. *(Opcional)* Agrega el **Asunto** y un fragmento del **Cuerpo** para que el motor también evalúe señuelos de ingeniería social aduanera (ej. *"guía retenida"*, *"pago de arancel urgente"*).
3. Pulsa **Ejecutar Análisis Forense** para ver al instante el veredicto, el puntaje sobre 100 y las señales detectadas.

---

## 4. Cómo Interpretar los Veredictos y el *Defanging*

### Escala de Riesgo (0 a 100 puntos)
| Rango | Estado | Acción Automática | Qué debe hacer el administrador |
| :---: | :--- | :--- | :--- |
| **0 - 29** | **CLEAN** (Verde) | Permanece en `INBOX`. | Ninguna acción requerida. |
| **30 - 59** | **SUSPICIOUS** (Ámbar) | Permanece en `INBOX` con alerta en consola. | Revisar la **Autopsia** en la Bitácora Forense y confirmar con el remitente por otra vía. |
| **60 - 100** | **QUARANTINED** (Carmesí) | Movido automáticamente a la carpeta `Cuarentena`. | No abrir los enlaces. Si confirmas que fue un falso positivo, puedes moverlo manualmente de vuelta a `INBOX` desde tu cliente de correo. |

### ¿Por qué las URLs se ven como `hxxps://ejemplo[.]com`?
A esta técnica de ciberseguridad se le llama **URL Defanging** (desarmado visual). El sistema reemplaza `http` por `hxxp` y los puntos por `[.]` para garantizar que **ningún analista pueda hacer clic por accidente** en un enlace malicioso mientras audita incidentes en la consola.

---

## 5. Preguntas Frecuentes (Solución Rápida)

* **La consola muestra "Sin conexión al servidor":** Verifica que el proceso `uvicorn` siga ejecutándose en la terminal.
* **Un correo nuevo no aparece en la consola:** Recuerda que el monitor revisa correos no leídos (`UNSEEN`) cada 15 segundos y requiere que `EMAIL_USER` y `EMAIL_PASSWORD` estén configurados en `.env`.
* **No tengo clave de VirusTotal:** El sistema sigue operando con normalidad usando la lista local de OpenPhish y las reglas heurísticas aduaneras.