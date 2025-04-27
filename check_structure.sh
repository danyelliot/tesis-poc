#!/bin/bash

# Verificar que los directorios y archivos necesarios existen
for dir in cmd/collector cmd/analyzer pkg/github pkg/models pkg/analyzer pkg/report internal/config internal/utils; do
  if [ ! -d "$dir" ]; then
    echo "Error: El directorio $dir no existe. Ejecute ./setup.sh para crear la estructura de directorios."
    exit 1
  fi
done

# Verificar archivos clave
files=(
  "cmd/collector/main.go"
  "cmd/analyzer/main.go"
  "pkg/github/client.go"
  "pkg/github/collector.go"
  "pkg/models/repository.go"
  "pkg/models/vulnerability.go"
  "pkg/analyzer/analyzer.go"
  "pkg/analyzer/detector.go"
  "pkg/analyzer/command_injection.go"
  "pkg/analyzer/unsafe_actions.go"
  "pkg/analyzer/secrets.go"
  "pkg/analyzer/permissions.go"
  "pkg/analyzer/pull_request_target.go"
  "pkg/analyzer/script_injection.go"
  "pkg/report/reporter.go"
  "pkg/report/markdown.go"
  "pkg/report/sarif.go"
  "internal/config/config.go"
  "internal/utils/file.go"
)

for file in "${files[@]}"; do
  if [ ! -f "$file" ]; then
    echo "Error: El archivo $file no existe o está vacío."
    exit 1
  else
    # Verificar si el archivo tiene contenido
    if [ ! -s "$file" ]; then
      echo "Error: El archivo $file está vacío."
      exit 1
    fi
  fi
done

echo "La estructura del proyecto es correcta. Todos los archivos necesarios existen y tienen contenido."
