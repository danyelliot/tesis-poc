#!/bin/bash

# Asegúrate de que el token de GitHub está disponible en una variable de entorno
# export GITHUB_PAT=tu_token_aquí

# Script para probar la herramienta de automatización GHAS

# Muestra los comandos disponibles
echo "Comando de ejemplo para GHAS Automation:"
echo ""
echo "1. Procesar un solo repositorio específico:"
echo "   ./ghasautomation -repo usuario/repositorio"
echo ""
echo "2. Procesar solo el primer repositorio encontrado en la búsqueda:"
echo "   ./ghasautomation -single -q \"path:.github/workflows language:go\""
echo ""
echo "3. Procesar múltiples repositorios con límite:"
echo "   ./ghasautomation -m 5 -q \"path:.github/workflows language:go\""
echo ""
echo "4. Procesar un repositorio sin GitLeaks o escaneo de contenedores:"
echo "   ./ghasautomation -single -gitleaks=false -containerscan=false"
echo ""
echo "5. Procesar y limpiar el fork después del análisis:"
echo "   ./ghasautomation -single -cleanup"
echo ""
echo "NOTA: Debes configurar la variable de entorno GITHUB_PAT con un token válido antes de ejecutar estos comandos."
echo "      Por ejemplo: export GITHUB_PAT=ghp_your_token_here"
