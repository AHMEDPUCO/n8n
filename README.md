# 🛡️ Security Tools MCP & REST Server

Este servidor es una plataforma robusta de orquestación de seguridad diseñada para integrar diversas herramientas de escaneo (SAST, SCA, DAST y Secretos) en flujos de trabajo automatizados, CI/CD y asistentes de IA.

Ofrece una interfaz dual:
1. **API REST (FastAPI):** Para integraciones tradicionales y dashboards.
2. **MCP Server (SSE):** Basado en el Model Context Protocol para uso directo con agentes de IA.

## 🚀 Características Principales

### 🔍 Análisis de Seguridad (Multitool)
El servidor actúa como un wrapper para las siguientes herramientas líderes de la industria:
- **SAST (Static Analysis):** `Semgrep`, `ESLint`, `Roslynator`.
- **SCA (Software Composition Analysis):** `Trivy`, `npm audit`, `govulncheck`, `dotnet list package`.
- **DAST (Dynamic Analysis):** Integración con `OWASP ZAP` (asíncrono).
- **Secrets Scanning:** `Gitleaks`.
- **SBOM:** Generación de archivos `CycloneDX`.

### 🛠️ Integraciones de Ecosistema
- **DefectDojo:** Carga automática de reportes de escaneo.
- **GitLab:** Comentarios automáticos en Merge Requests con los hallazgos.
- **Dependency-Track:** Integración para gestión de componentes (SBOM).

### 🤖 Inteligencia de Proyecto
- **Análisis de tipo de proyecto:** Detecta automáticamente si un proyecto usa Docker, Python, Node.js, etc.
- **Evaluación de Riesgo:** Genera un score de riesgo basado en el contexto del repositorio.
- **Contexto de Git:** Obtiene archivos cambiados en commits específicos para escaneos incrementales.

## 📋 Requisitos Previos

Para que todas las herramientas funcionen, el entorno debe tener instalado:
- **Python 3.10+**
- **Docker** (opcional, para escaneo de imágenes)
- **Herramientas de CLI:** `git`, `npm`, `semgrep`, `trivy`, `gitleaks`, `go`, `dotnet`.
- **OWASP ZAP Server:** Accesible vía URL (por defecto `http://zap:8080`).

## ⚙️ Configuración (Variables de Entorno)

| Variable | Descripción | Valor Defecto |
| :--- | :--- | :--- |
| `PORT` | Puerto del servidor | `8088` |
| `SCAN_TARGETS_DIR` | Directorio raíz para escaneos | `/scan-targets` |
| `REPORTS_DIR` | Directorio donde se guardan reportes | `/app/reports` |
| `ZAP_URL` | URL de la API de OWASP ZAP | `http://zap:8080` |
| `DEFECTDOJO_URL` | URL de la instancia de DefectDojo | - |
| `MCP_AUTH_TOKEN` | Token opcional para asegurar la API | - |

## 🚀 Uso Rápido

### Ejecutar el servidor
```bash
python server.py
```

### Endpoints Principales (REST)
- `GET /health`: Estado del servicio.
- `GET /system/health`: Disponibilidad de herramientas externas.
- `POST /tools/semgrep`: Ejecutar escaneo SAST.
- `POST /tools/zap/quick/start`: Iniciar escaneo DAST asíncrono.
- `GET /reports`: Listar reportes generados.

### Conexión MCP
El servidor expone el endpoint `/sse` para clientes de IA que soporten el protocolo MCP.

## 📂 Estructura de Reportes
Todos los escaneos pueden generar reportes persistentes en formato JSON seleccionando el flag `save_report_flag: true`. Los reportes se almacenan en la ruta configurada en `REPORTS_DIR` con un timestamp único.

---
*Desarrollado para flujos de seguridad avanzados y DevSecOps.*
