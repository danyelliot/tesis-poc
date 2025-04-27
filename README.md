# Analizador de Seguridad de GitHub Actions Workflows

Esta herramienta analiza flujos de trabajo de GitHub Actions en busca de vulnerabilidades de seguridad comunes, proporcionando informes detallados para ayudar a mejorar la seguridad de las configuraciones de CI/CD.

## 📋 Índice

- [Características](#características)
- [Instalación](#instalación)
- [Uso](#uso)
- [Formatos de Salida](#formatos-de-salida)
- [Tipos de Vulnerabilidades Detectadas](#tipos-de-vulnerabilidades-detectadas)
- [Flujo de Trabajo](#flujo-de-trabajo)
- [Contribuciones](#contribuciones)
- [Licencia](#licencia)

## ✨ Características

- Detecta múltiples tipos de vulnerabilidades comunes en flujos de trabajo de GitHub Actions
- Genera reportes detallados en formatos estándar (Markdown y SARIF)
- Integrable con CI/CD y compatible con GitHub Code Scanning
- Análisis estático sin necesidad de ejecutar los workflows
- Configurable para procesar grandes cantidades de repositorios

## 🔧 Instalación

### Requisitos previos

- Go 1.17 o superior
- Token de GitHub con permisos para acceder a los repositorios a analizar

### Pasos de instalación

1. Clonar el repositorio:
```bash
git clone https://github.com/cmalvaceda/tesis-poc.git
cd tesis-poc
```

2. Instalar dependencias:
```bash
go mod download
```

3. Configurar el token de GitHub:
```bash
# Crear archivo .env en la raíz del proyecto
echo "GITHUB_PAT=tu_token_personal_de_github" > .env
```

## 🚀 Uso

### Paso 1: Recolectar workflows de GitHub

```bash
go run main.go -m 100 -o repositorios_con_workflows.txt
```

Opciones:
- `-m`: Número máximo de repositorios a procesar
- `-o`: Archivo de salida
- `-q`: Consulta personalizada para buscar repositorios (predeterminado: `path:.github/workflows`)

### Paso 2: Analizar workflows en busca de vulnerabilidades

```bash
go run workflow_analyzer.go -i repositorios_con_workflows.txt -o reporte_vulnerabilidades.md -m 50
```

Opciones:
- `-i`: Archivo de entrada con lista de repositorios y workflows
- `-o`: Archivo de salida para el reporte
- `-m`: Número máximo de repositorios a analizar
- `-f`: Formato del reporte (`md` para Markdown, `sarif` para SARIF JSON)

## 📊 Formatos de Salida

### Markdown

El reporte en Markdown incluye:
- Resumen ejecutivo de vulnerabilidades encontradas
- Estadísticas por tipo y severidad
- Análisis detallado de cada tipo de vulnerabilidad
- Ejemplos de código vulnerable
- Recomendaciones de mitigación

### SARIF

El formato SARIF (Static Analysis Results Interchange Format) es un estándar JSON para resultados de análisis estático.

Ventajas:
- Compatible con GitHub Code Scanning
- Integrable con otras herramientas de seguridad
- Estructura estándar que facilita el procesamiento automatizado

Para generar un reporte SARIF:

```bash
go run workflow_analyzer.go -i repositorios_con_workflows.txt -o reporte.sarif -f sarif
```

## 🛡️ Tipos de Vulnerabilidades Detectadas

- **Command Injection**: Inyecciones de comandos a través de inputs no sanitizados
- **Unsafe Action Reference**: Referencias inseguras a acciones de terceros
- **Secret Exposure**: Exposición de secretos en registros o variables de entorno
- **Excessive Permissions**: Permisos excesivos o no limitados
- **Unsafe pull_request_target**: Uso peligroso del evento pull_request_target
- **Script Injection**: Inyecciones en scripts multilinea

## 📝 Flujo de Trabajo

Consulta [WORKFLOW.md](WORKFLOW.md) para una descripción detallada del flujo de trabajo interno de la herramienta.

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue primero para discutir lo que te gustaría cambiar o agregar.

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.
