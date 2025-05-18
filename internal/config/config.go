package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	GithubToken string
}

func LoadConfig() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("no se pudo cargar el archivo .env: %w", err)
	}

	githubToken := os.Getenv("GITHUB_PAT")

	return &Config{
		GithubToken: githubToken,
	}, nil
}
