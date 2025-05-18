#!/bin/bash

# Script para ejecutar el flujo completo de recolección y análisis GHAS
# Uso: ./ghas-full-flow.sh [opciones]

# Colores para la salida
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # Sin color

# Función para mostrar la ayuda
show_help() {
  echo -e "${BLUE}=== Herramienta de Flujo Completo de Análisis GHAS para Workflows ===${NC}"
  echo ""
  echo -e "Este script ejecuta el flujo completo de recolección de repositorios con workflows y"
  echo -e "configuración de GitHub Advanced Security (GHAS) para análisis automático."
  echo ""
  echo -e "${YELLOW}Uso:${NC} $0 [opciones]"
  echo ""
  echo -e "${GREEN}Opciones:${NC}"
  echo -e "  -h, --help             Muestra esta ayuda"
  echo -e "  -m, --max NUM          Establece el número máximo de repositorios a procesar (default: 10)"
  echo -e "  -o, --output ARCHIVO   Establece el archivo de salida para la lista de repositorios"
  echo -e "  -q, --query CONSULTA   Define la consulta de búsqueda GitHub (default: path:.github/workflows)"
  echo -e "  -r, --repo REPO        Procesa un repositorio específico (formato: propietario/nombre)"
  echo -e "  --no-gitleaks          Desactiva el análisis de secretos con GitLeaks"
  echo -e "  --no-container         Desactiva el análisis de contenedores Docker"
  echo -e "  --cleanup              Elimina los forks después del análisis"
  echo -e "  --collect-only         Solo ejecuta la fase de recolección, sin análisis GHAS"
  echo -e "  --userinfo             Muestra información del usuario autenticado y sus forks"
  echo -e "  --force                Fuerza la creación/actualización de ramas existentes"
  echo ""
  echo -e "${YELLOW}Ejemplos:${NC}"
  echo -e "  $0 -m 5                            # Procesar 5 repositorios"
  echo -e "  $0 -r usuario/repo                 # Procesar un repositorio específico"
  echo -e "  $0 -q \"path:.github/workflows language:go\" # Buscar repos de Go con workflows"
  echo -e "  $0 --collect-only -o repos.txt     # Solo recolectar sin aplicar GHAS"
}

# Variables predeterminadas
MAX_REPOS=10
OUTPUT_FILE="repos_workflows_ghas.txt"
QUERY="path:.github/workflows"
SPECIFIC_REPO=""
ENABLE_GITLEAKS=true
ENABLE_CONTAINER=true
CLEANUP=false
COLLECT_ONLY=false
USER_INFO=false
FORCE_UPDATE=false

# Procesar argumentos
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      show_help
      exit 0
      ;;
    -m|--max)
      MAX_REPOS="$2"
      shift 2
      ;;
    -o|--output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    -q|--query)
      QUERY="$2"
      shift 2
      ;;
    -r|--repo)
      SPECIFIC_REPO="$2"
      shift 2
      ;;
    --no-gitleaks)
      ENABLE_GITLEAKS=false
      shift
      ;;
    --no-container)
      ENABLE_CONTAINER=false
      shift
      ;;
    --cleanup)
      CLEANUP=true
      shift
      ;;
    --collect-only)
      COLLECT_ONLY=true
      shift
      ;;
    --userinfo)
      USER_INFO=true
      shift
      ;;
    --force)
      FORCE_UPDATE=true
      shift
      ;;
    *)
      echo -e "${RED}Error: Opción desconocida $1${NC}"
      show_help
      exit 1
      ;;
  esac
done

echo -e "${BLUE}=== Iniciando Flujo Completo de Análisis GHAS ===${NC}"

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

# Compilar la herramienta si no existe
if [ ! -f "ghasfullflow" ]; then
    echo -e "${YELLOW}Compilando herramienta de flujo completo...${NC}"
    go build -o ghasfullflow ./cmd/ghasfullflow
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error al compilar la herramienta${NC}"
        exit 1
    fi
fi

# Construir comando
CMD="./ghasfullflow -m $MAX_REPOS -o $OUTPUT_FILE -q \"$QUERY\" -gitleaks=$ENABLE_GITLEAKS -containerscan=$ENABLE_CONTAINER -cleanup=$CLEANUP"

# Agregar opciones específicas
if [ -n "$SPECIFIC_REPO" ]; then
    CMD="$CMD -repo $SPECIFIC_REPO"
fi

# Agregar opción para solo recolección (sin análisis)
if [ "$COLLECT_ONLY" = true ]; then
    CMD="$CMD"
else
    CMD="$CMD -all"
fi

# Agregar opción para mostrar información del usuario
if [ "$USER_INFO" = true ]; then
    CMD="$CMD -userinfo"
fi

# Agregar opción para forzar actualización de ramas existentes
if [ "$FORCE_UPDATE" = true ]; then
    CMD="$CMD -force"
fi

# Mostrar configuración
echo -e "${YELLOW}Configuración:${NC}"
echo -e "  Max repositorios:   ${GREEN}$MAX_REPOS${NC}"
echo -e "  Archivo de salida:  ${GREEN}$OUTPUT_FILE${NC}"
echo -e "  Consulta de búsqueda: ${GREEN}$QUERY${NC}"
if [ -n "$SPECIFIC_REPO" ]; then
    echo -e "  Repositorio específico: ${GREEN}$SPECIFIC_REPO${NC}"
fi
echo -e "  Análisis GitLeaks:  ${GREEN}$ENABLE_GITLEAKS${NC}"
echo -e "  Análisis Containers: ${GREEN}$ENABLE_CONTAINER${NC}"
echo -e "  Limpieza de forks:  ${GREEN}$CLEANUP${NC}"
echo -e "  Solo recolección:   ${GREEN}$COLLECT_ONLY${NC}"
echo -e "  Info de usuario:    ${GREEN}$USER_INFO${NC}"
echo -e "  Forzar actualización: ${GREEN}$FORCE_UPDATE${NC}"
echo ""

# Ejecutar comando
echo -e "${BLUE}Ejecutando: $CMD${NC}"
eval $CMD

# Comprobar resultado
if [ $? -eq 0 ]; then
    echo -e "${GREEN}¡Flujo completo ejecutado exitosamente!${NC}"
    
    if [ "$USER_INFO" = true ]; then
        echo -e "${YELLOW}Información del usuario mostrada correctamente.${NC}"
    elif [ "$COLLECT_ONLY" = true ]; then
        echo -e "${YELLOW}Resultados de la recolección guardados en:${NC} $OUTPUT_FILE"
        echo -e "${YELLOW}Para ejecutar el análisis GHAS en estos repositorios, ejecuta:${NC}"
        echo -e "$0 --no-collect -i $OUTPUT_FILE"
    else
        echo -e "${YELLOW}El análisis GHAS ha sido configurado y debería comenzar automáticamente en los repositorios fork.${NC}"
        echo -e "${YELLOW}Los resultados del análisis estarán disponibles en la pestaña 'Seguridad' de cada repositorio fork en GitHub.${NC}"
    fi
else
    echo -e "${RED}Error al ejecutar el flujo completo${NC}"
    exit 1
fi
