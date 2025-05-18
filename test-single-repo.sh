#!/bin/bash

# Script para probar la funcionalidad de GHAS automation con un solo repositorio
# Uso: ./test-single-repo.sh [propietario/nombre] [opciones]
# Opciones:
#   --force    Forzar la creación/actualización de la rama de análisis
#
# Si no se proporciona un repositorio específico, se usará el primer repositorio encontrado

# Colores para la salida
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # Sin color

echo -e "${YELLOW}=== Preparando prueba de automatización GHAS ===${NC}"

# Verificar si se ha construido la herramienta
if [ ! -f "ghasfullflow" ]; then
    echo -e "${YELLOW}Compilando herramienta de automatización GHAS...${NC}"
    go build -o ghasfullflow ./cmd/ghasfullflow
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error al compilar la herramienta${NC}"
        exit 1
    fi
fi

# Verificar token de GitHub
if [ -z "$GITHUB_PAT" ]; then
    if [ -f .env ]; then
        export $(grep -v '^#' .env | xargs)
    fi
    
    if [ -z "$GITHUB_PAT" ]; then
        echo -e "${RED}Error: No se encontró el token de GitHub (GITHUB_PAT)${NC}"
        echo "Asegúrate de configurar la variable de entorno GITHUB_PAT o incluirla en el archivo .env"
        exit 1
    fi
fi

# Variables
FORCE_UPDATE=false
REPO=""

# Procesar argumentos
while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      FORCE_UPDATE=true
      shift
      ;;
    *)
      # Si no es una opción reconocida, asumimos que es el repositorio
      if [[ "$1" != -* ]]; then
        REPO="$1"
      else
        echo -e "${RED}Error: Opción desconocida $1${NC}"
        exit 1
      fi
      shift
      ;;
  esac
done

# Construir comando
CMD="./ghasfullflow"

# Determinar el modo de ejecución
if [ -n "$REPO" ]; then
    # Si se proporciona un repositorio específico, usarlo
    echo -e "${GREEN}Procesando repositorio específico: $REPO${NC}"
    CMD="$CMD -repo $REPO"
else
    # De lo contrario, usar el primer repositorio encontrado
    echo -e "${GREEN}Procesando el primer repositorio encontrado${NC}"
    CMD="$CMD -m 1"
fi

# Agregar opciones adicionales
CMD="$CMD -cleanup=false"

# Agregar opción de forzar actualización si se especificó
if [ "$FORCE_UPDATE" = true ]; then
    echo -e "${YELLOW}Se forzará la actualización de las ramas existentes${NC}"
    CMD="$CMD -force"
fi

# Ejecutar comando
echo -e "${YELLOW}Ejecutando: $CMD${NC}"
eval $CMD

echo -e "${GREEN}¡Prueba completada!${NC}"
