package main

import (
	"flag"
	"log"
	"os"

	"github.com/cmalvaceda/tesis-poc/internal/config"
	"github.com/cmalvaceda/tesis-poc/pkg/analyzer"
	"github.com/cmalvaceda/tesis-poc/pkg/github"
	"github.com/cmalvaceda/tesis-poc/pkg/models"
	"github.com/cmalvaceda/tesis-poc/pkg/report"
)

func main() {
	_, err := config.LoadConfig() // Changed: removed cfg variable, just check for error
	if err != nil {
		log.Printf("Advertencia: %v", err)
	}

	inputFile := flag.String("i", "actions_repos_workflows_go.txt", "Archivo con la lista de repositorios y workflows")
	outputFile := flag.String("o", "workflow_vulnerabilities.txt", "Archivo para guardar el reporte de vulnerabilidades")
	maxRepos := flag.Int("m", 50, "Número máximo de repositorios a analizar")
	format := flag.String("f", "md", "Formato del reporte: md (markdown), sarif (JSON estándar)")
	flag.Parse()

	githubToken := os.Getenv("GITHUB_PAT")
	if githubToken == "" {
		log.Fatal("Error: Token de GitHub (GITHUB_PAT) no encontrado")
	}

	client, err := github.NewClient(githubToken)
	if err != nil {
		log.Fatalf("Error al crear cliente de GitHub: %v", err)
	}

	repos, err := models.ReadRepoWorkflows(*inputFile)
	if err != nil {
		log.Fatalf("Error al leer archivo de entrada: %v", err)
	}

	log.Printf("Se encontraron %d repositorios para analizar", len(repos))

	workflowAnalyzer := analyzer.NewWorkflowAnalyzer(client)
	vulnerabilities, err := workflowAnalyzer.AnalyzeRepositories(repos, *maxRepos)
	if err != nil {
		log.Fatalf("Error durante el análisis: %v", err)
	}

	if *format == "sarif" {
		reporter := report.NewSARIFReporter()
		err = reporter.GenerateReport(vulnerabilities, *outputFile)
	} else {
		reporter := report.NewMarkdownReporter()
		err = reporter.GenerateReport(vulnerabilities, *outputFile)
	}

	if err != nil {
		log.Fatalf("Error al generar el reporte: %v", err)
	}

	log.Printf("\nAnálisis completado. Total de vulnerabilidades encontradas: %d", len(vulnerabilities))
	log.Printf("Reporte guardado en '%s'", *outputFile)
}
