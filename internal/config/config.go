package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

// Config almacena la configuración de la aplicación
type Config struct {
	GithubToken string
}

// LoadConfig carga la configuración desde variables de entorno y archivo .env
func LoadConfig() (*Config, error) {
	// Intentar cargar .env pero no fallar si no existe
	err := godotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("no se pudo cargar el archivo .env: %w", err)
	}

	// Cargar token de GitHub - esto usará el valor de .env si se cargó correctamente
	githubToken := os.Getenv("GITHUB_PAT")

	return &Config{
		GithubToken: githubToken,
	}, nil
}
