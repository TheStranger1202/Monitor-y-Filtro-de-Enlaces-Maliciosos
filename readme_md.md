# 🛡️ Sistema de Detección de Enlaces Maliciosos en Plataformas de Correo Institucional

Proyecto universitario orientado a la detección preventiva y remediación automatizada de enlaces maliciosos (*phishing*, *malware* y suplantación de identidad) en plataformas de correo institucional de compañías de importación y exportación ubicadas en el municipio Chacao, Miranda, Venezuela.

---

## 📋 Descripción del Problema y Solución

Las empresas del sector aduanero y de comercio exterior reciben diariamente un alto volumen de comunicaciones con enlaces externos (tracking de navieras, notificaciones arancelarias, manifiestos de carga y facturación), lo que las convierte en un blanco crítico para ataques de ingeniería social.

Este sistema implementa una arquitectura de **Seguridad de Correo Integrada (ICES — *Integrated Cloud Email Security*)** que opera mediante monitoreo continuo por protocolo **IMAP** y un **motor híbrido de análisis en 3 capas**, aislando automáticamente los correos sospechosos en una carpeta de cuarentena antes de que el usuario interactúe con ellos.

---

## 🏗️ Arquitectura del Sistema

El flujo de procesamiento consta de cuatro etapas principales:

1. **Ingesta y Extracción Segura (IMAP + MIME/HTML):**
   * Conexión segura vía SSL/TLS (`IMAP4_SSL`) a la bandeja de entrada institucional.
   * Decodificación de estructuras multiparte (MIME) y análisis DOM del HTML para extraer tanto los atributos `href` reales como los textos visibles de cada enlace.
2. **Motor de Detección Híbrido (3 Capas):**
   * **Capa 1 — Caché Local y Listas de Control (SQLite):** Consulta instantánea contra una lista blanca de dominios legítimos verificados y una base de datos local alimentada por *feeds* públicos de inteligencia de amenazas (URLhaus / OpenPhish).
   * **Capa 2 — Inteligencia de Amenazas Externa (VirusTotal API v3):** Evaluación reputacional mediante consulta a múltiples motores antivirus con gestión de límite de tasa (*rate limiting*).
   * **Capa 3 — Heurística Contextual (Sector Importación/Exportación):** Sistema de puntuación ponderada (*scoring*) que evalúa palabras clave del rubro aduanero, detección de *typosquatting* sobre navieras/couriers, uso de direcciones IP directas, acortadores de URL y discrepancias entre enlace visible y destino real.
3. **Remediación Automatizada:**
   * Los correos que superan el umbral de riesgo son trasladados automáticamente a la carpeta `Cuarentena` del buzón y registrados en la base de datos para auditoría.
4. **Panel de Control Web (Dashboard):**
   * Interfaz web desarrollada en **FastAPI** para visualizar métricas en tiempo real, auditar incidentes bloqueados y analizar URLs de forma manual.

---

## 📁 Estructura del Proyecto

```text
phishguard-chacao/
├── .env.example              # Plantilla de variables de entorno
├── .gitignore                # Exclusiones de control de versiones
├── LICENSE                   # Licencia MIT
├── README.md                 # Documentación principal
├── requirements.txt          # Dependencias del proyecto
├── docs/                     # Documentación académica y técnica
│   ├── arquitectura.md       # Diseño detallado y matriz de riesgo
│   └── estandar_commits.md   # Convención de commits del repositorio
├── app/                      # Código fuente principal
│   ├── main.py               # Punto de entrada FastAPI y ciclo de vida IMAP
│   ├── core/                 # Configuración global y variables de entorno
│   ├── db/                   # Modelos de datos y conexión SQLite
│   ├── services/             # Monitor IMAP, extractor HTML y motor de 3 capas
│   ├── api/                  # Endpoints REST del Dashboard
│   └── frontend/             # Plantillas HTML y hojas de estilo CSS
├── scripts/                  # Utilidades de actualización de feeds y pruebas
└── tests/                    # Pruebas unitarias y de integración
```

---

## ⚙️ Requisitos Previos

* **Sistema Operativo:** Debian 13 (o distribución Linux compatible).
* **Lenguaje:** Python 3.11 o superior.
* **Cuenta de Correo:** Buzón con acceso IMAP habilitado (ej. Gmail con *Contraseña de Aplicación* o servidor institucional).
* **API Externa:** Clave de API gratuita de [VirusTotal](https://www.virustotal.com/).

---

## 🚀 Instalación y Configuración

1. **Clonar el repositorio:**
   ```bash
   git clone https://github.com/TU_USUARIO/phishguard-chacao.git
   cd phishguard-chacao
   ```

2. **Crear y activar el entorno virtual:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Instalar dependencias:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configurar variables de entorno:**
   ```bash
   cp .env.example .env
   ```
   Edita el archivo `.env` con tus credenciales IMAP y tu clave de VirusTotal.

5. **Actualizar la base de datos local de amenazas:**
   ```bash
   python scripts/update_feeds.py
   ```

---

## 🧪 Flujo de Demostración (Entorno de Pruebas)

Para validar el funcionamiento del sistema de forma segura:
1. Iniciar el servidor web y el servicio de monitoreo IMAP.
2. Enviar un correo de prueba hacia la cuenta monitoreada conteniendo enlaces de prueba controlados o patrones de *phishing* aduanero.
3. Verificar el traslado automático del mensaje hacia la carpeta `Cuarentena` y la generación de la alerta correspondiente en el Dashboard.

---

## 🤝 Estándar de Desarrollo

Este repositorio sigue la especificación **Conventional Commits** documentada en `docs/estandar_commits.md` para garantizar la trazabilidad del código.

---

## 📄 Licencia

Este proyecto está distribuido bajo la **Licencia MIT**. Consulta el archivo `LICENSE` para más detalles.