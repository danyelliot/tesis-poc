#!/bin/bash

# Script para corregir importaciones en todos los archivos Go del proyecto

echo "Corrigiendo importaciones en todos los archivos Go..."

# Buscamos todos los archivos Go y procesamos cada uno
find . -name "*.go" | while read file; do
  # Cambiamos 'github.RateLimitError' a 'gh.RateLimitError' donde gh es el alias
  sed -i '' 's/github\.RateLimitError/gh.RateLimitError/g' "$file"
  
  # Verificamos si el archivo importa github.com/google/go-github/v60/github
  # sin alias y usa tipos de ese paquete directamente
  if grep -q 'github\.com/google/go-github/v60/github' "$file" && ! grep -q 'gh \"github\.com/google/go-github/v60/github\"' "$file"; then
    # Si encontramos imports del paquete github sin alias
    # y uso directo de tipos como github.XYZ, añadimos alias
    sed -i '' 's/\"github\.com\/google\/go-github\/v60\/github\"/gh \"github\.com\/google\/go-github\/v60\/github\"/g' "$file"
    # Y cambiamos las referencias directas a github.XYZ por gh.XYZ
    sed -i '' 's/github\.\([A-Z][a-zA-Z]*\)/gh.\1/g' "$file"
  fi
  
  echo "Procesado: $file"
done

echo "¡Importaciones corregidas! Ahora intenta ejecutar 'go mod tidy' y luego tus comandos."
