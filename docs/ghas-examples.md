# Ejemplos de Prueba para Automatización GHAS

Este documento proporciona ejemplos prácticos para probar las funcionalidades de automatización GHAS en diferentes escenarios.

## Pruebas Básicas

### Analizar un único repositorio

```bash
# Ver información detallada del usuario actual y sus forks
./ghas-full-flow.sh --userinfo

# Analizar un repositorio específico con configuración predeterminada
./ghas-full-flow.sh -r warrenbuckley/Setup-MSBuild

# Analizar un repositorio y forzar actualización de configuraciones existentes
./ghas-full-flow.sh -r microsoft/setup-msbuild --force
```

### Recolectar repositorios sin aplicar GHAS

```bash
# Recolectar hasta 5 repositorios con workflows de GitHub Actions
./ghas-full-flow.sh --collect-only -m 5 -o repositorios_candidatos.txt

# Recolectar repositorios JavaScript con workflows
./ghas-full-flow.sh --collect-only -q "path:.github/workflows language:javascript" -m 3 -o repos_javascript.txt
```

### Aplicar GHAS a repositorios previamente recolectados

```bash
# Aplicar GHAS a los repositorios en el archivo especificado
./test-single-repo.sh -i repositorios_candidatos.txt
```

## Pruebas Avanzadas

### Personalizar herramientas de seguridad

```bash
# Aplicar GHAS sin GitLeaks
./ghas-full-flow.sh -r octocat/Hello-World --no-gitleaks

# Aplicar GHAS sin análisis de contenedores
./ghas-full-flow.sh -r octocat/Hello-World --no-container

# Aplicar solo CodeQL y Dependabot
./ghas-full-flow.sh -r octocat/Hello-World --no-gitleaks --no-container
```

### Gestionar forks

```bash
# Crear forks y eliminarlos después del análisis
./ghas-full-flow.sh -r octocat/Hello-World --cleanup

# Gestionar forks existentes con fuerza
./ghas-full-flow.sh -r octocat/Hello-World --force
```

## Ejemplos por Lenguaje

### Python

```bash
# Analizar un repositorio Python específico
./ghas-full-flow.sh -r psf/requests

# Buscar repositorios Python con workflows
./ghas-full-flow.sh --collect-only -q "path:.github/workflows language:python" -m 5 -o python_repos.txt
```

### JavaScript/TypeScript

```bash
# Analizar un repositorio JavaScript/TypeScript
./ghas-full-flow.sh -r facebook/react

# Buscar proyectos de Next.js
./ghas-full-flow.sh --collect-only -q "path:.github/workflows filename:next.config.js" -m 3
```

### Go

```bash
# Analizar un repositorio Go
./ghas-full-flow.sh -r kubernetes/kubectl

# Buscar proyectos Go con Dockerfile
./ghas-full-flow.sh --collect-only -q "path:.github/workflows language:go filename:Dockerfile" -m 3
```

## Casos de Prueba Específicos

### Detección Multi-lenguaje

Repositorios con múltiples lenguajes para probar la detección inteligente:

```bash
# Proyecto full-stack con backend y frontend
./ghas-full-flow.sh -r vercel/next.js

# Proyecto con microservicios en diferentes lenguajes
./ghas-full-flow.sh -r GoogleCloudPlatform/microservices-demo
```

### Repositorios con características especiales

```bash
# Repositorio con contenedores Docker
./ghas-full-flow.sh -r docker/awesome-compose

# Repositorio con muchas dependencias
./ghas-full-flow.sh -r gatsbyjs/gatsby
```

## Verificación de Resultados

Para verificar que la automatización GHAS funciona correctamente:

1. Navega al fork creado en tu cuenta de GitHub
2. Ve a la pestaña "Actions" para verificar que los workflows se están ejecutando
3. Espera a que los análisis se completen
4. Ve a la pestaña "Security" para ver los resultados:
   - "Code scanning alerts" para resultados de CodeQL
   - "Dependabot alerts" para vulnerabilidades de dependencias
   - "Secret scanning alerts" para secretos detectados

## Solución de Problemas Comunes

### Error: "No se pudo hacer fork del repositorio"

**Posible causa**: Límite de forks o ya existe un fork.
**Solución**: Verificar forks existentes con `--userinfo` y eliminar forks no utilizados.

### Error: "No se pudo detectar lenguaje"

**Posible causa**: Repositorio sin archivos de código reconocible.
**Solución**: Especificar manualmente el lenguaje o seleccionar otro repositorio.

### Error: "No se pudo empujar a la rama"

**Posible causa**: Conflictos con la rama existente.
**Solución**: Usar la opción `--force` para sobrescribir los cambios existentes.
