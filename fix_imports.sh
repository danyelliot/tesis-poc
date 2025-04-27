echo "Corrigiendo importaciones en todos los archivos Go..."

find . -name "*.go" | while read file; do
  sed -i '' 's/github\.RateLimitError/gh.RateLimitError/g' "$file"
  
  if grep -q 'github\.com/google/go-github/v60/github' "$file" && ! grep -q 'gh \"github\.com/google/go-github/v60/github\"' "$file"; then
    sed -i '' 's/\"github\.com\/google\/go-github\/v60\/github\"/gh \"github\.com\/google\/go-github\/v60\/github\"/g' "$file"
    sed -i '' 's/github\.\([A-Z][a-zA-Z]*\)/gh.\1/g' "$file"
  fi
  
  echo "Procesado: $file"
done

echo "¡Importaciones corregidas! Ahora intenta ejecutar 'go mod tidy' y luego tus comandos."
