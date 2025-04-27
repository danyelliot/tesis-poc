package main

import (
	"flag"
	"log"
	"os"
	"strconv"

	"github.com/cmalvaceda/tesis-poc/internal/config"
	"github.com/cmalvaceda/tesis-poc/pkg/github"
	"github.com/cmalvaceda/tesis-poc/pkg/models"
)

const (
	defaultOutputFile = "actions_repos_workflows_go.txt"
	defaultMaxRepos   = 5000
)

func main() {
	// Cargar configuración
	_, err := config.LoadConfig()
	if err != nil {
		log.Printf("Advertencia: %v", err)
	}

	// Procesar argumentos
	query := flag.String("q", github.DefaultSearchQuery, "Consulta de búsqueda de GitHub. Puedes añadir más filtros.")
	outputFile := flag.String("o", defaultOutputFile, "Archivo de salida para guardar la lista de repositorios y sus workflows.")
	maxReposStr := flag.String("m", strconv.Itoa(defaultMaxRepos), "Número máximo de repositorios a procesar.")
	flag.Parse()

	maxRepos, err := strconv.Atoi(*maxReposStr)
	if err != nil || maxRepos <= 0 {
		log.Fatalf("Error: El número máximo de repositorios (-m) debe ser un entero positivo: %v", err)
	}

	// Verificar token
	githubToken := os.Getenv("GITHUB_PAT")
	if githubToken == "" {
		log.Fatal("Error: Token de GitHub (GITHUB_PAT) no encontrado en las variables de entorno o en el archivo .env.")
	}

	// Crear cliente GitHub
	client, err := github.NewClient(githubToken)
	if err != nil {
		log.Fatalf("Error al crear cliente de GitHub: %v", err)
	}

	// Buscar repositorios con workflows
	log.Printf("Realizando búsqueda con consulta: '%s'\n", *query)
	collector := github.NewWorkflowCollector(client, maxRepos)
	repoWorkflows, err := collector.CollectWorkflows(*query)
	if err != nil {
		log.Fatalf("Error al buscar repositorios: %v", err)
	}

	log.Printf("\nBúsqueda y procesamiento completados. Total de repositorios con workflows encontrados: %d\n", len(repoWorkflows))

	// Guardar resultados
	err = models.SaveWorkflowsToFile(repoWorkflows, *outputFile)
	if err != nil {
		log.Fatalf("Error al guardar en el archivo: %v", err)
	}
}
