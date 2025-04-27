RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

show_help() {
  echo -e "${BLUE}Analizador de Seguridad de GitHub Actions Workflows${NC}"
  echo ""
  echo "Uso:"
  echo -e "  ${YELLOW}./run.sh collect${NC} - Recolectar workflows de GitHub"
  echo -e "  ${YELLOW}./run.sh analyze${NC} - Analizar workflows en busca de vulnerabilidades"
  echo -e "  ${YELLOW}./run.sh all${NC} - Ejecutar recolección y análisis en secuencia"
  echo -e "  ${YELLOW}./run.sh help${NC} - Mostrar esta ayuda"
  echo ""
  echo "Opciones adicionales:"
  echo "  Para pasar argumentos a los comandos, agrégalos después del comando base:"
  echo -e "  ${YELLOW}./run.sh collect -m 100${NC} - Recolectar workflows limitando a 100 repositorios"
  echo -e "  ${YELLOW}./run.sh analyze -f sarif${NC} - Analizar y generar reporte en formato SARIF"
  echo ""
}

if [ -z "$GITHUB_PAT" ] && [ ! -f .env ]; then
  echo -e "${RED}Error: No se encontró el token de GitHub.${NC}"
  echo "Debe configurar la variable de entorno GITHUB_PAT o crear un archivo .env con GITHUB_PAT=su_token"
  exit 1
fi

case "$1" in
  collect)
    shift
    echo -e "${GREEN}Recolectando workflows de GitHub...${NC}"
    go run cmd/collector/main.go "$@"
    ;;
  analyze)
    shift
    echo -e "${GREEN}Analizando workflows en busca de vulnerabilidades...${NC}"
    go run cmd/analyzer/main.go "$@"
    ;;
  all)
    shift
    echo -e "${GREEN}Ejecutando recolección y análisis en secuencia...${NC}"
    echo -e "${BLUE}Paso 1: Recolectando workflows${NC}"
    go run cmd/collector/main.go "$@"
    if [ $? -eq 0 ]; then
      echo -e "${BLUE}Paso 2: Analizando vulnerabilidades${NC}"
      go run cmd/analyzer/main.go "$@"
    else
      echo -e "${RED}La recolección falló. No se ejecutará el análisis.${NC}"
      exit 1
    fi
    ;;
  help|*)
    show_help
    ;;
esac
