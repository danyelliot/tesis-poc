package analyzer

import (
	"log"
	"time"

	"github.com/cmalvaceda/tesis-poc/pkg/github"
	"github.com/cmalvaceda/tesis-poc/pkg/models"
	"gopkg.in/yaml.v3"
)

// WorkflowAnalyzer gestiona el análisis de vulnerabilidades en workflows
type WorkflowAnalyzer struct {
	client *github.Client
}

// NewWorkflowAnalyzer crea un nuevo analizador de workflows
func NewWorkflowAnalyzer(client *github.Client) *WorkflowAnalyzer {
	return &WorkflowAnalyzer{
		client: client,
	}
}

// AnalyzeRepositories analiza los workflows de una lista de repositorios
func (wa *WorkflowAnalyzer) AnalyzeRepositories(repos []models.RepoInfo, maxRepos int) ([]models.Vulnerability, error) {
	var allVulnerabilities []models.Vulnerability
	count := 0

	for _, repo := range repos {
		if count >= maxRepos {
			log.Printf("Alcanzado el límite de %d repositorios", maxRepos)
			break
		}

		log.Printf("Analizando repositorio %s (%d/%d)", repo.FullName, count+1, maxRepos)

		// Analizar cada workflow del repositorio
		repoVulnerabilities, err := wa.analyzeWorkflows(repo)
		if err != nil {
			log.Printf("Error al analizar workflows para %s: %v", repo.FullName, err)
			continue
		}

		if len(repoVulnerabilities) > 0 {
			allVulnerabilities = append(allVulnerabilities, repoVulnerabilities...)
			log.Printf("  Se encontraron %d vulnerabilidades potenciales", len(repoVulnerabilities))
		} else {
			log.Printf("  No se encontraron vulnerabilidades")
		}

		count++
		time.Sleep(500 * time.Millisecond) // Pequeña pausa para evitar límites de tasa
	}

	return allVulnerabilities, nil
}

// analyzeWorkflows analiza los workflows de un repositorio
func (wa *WorkflowAnalyzer) analyzeWorkflows(repo models.RepoInfo) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	for _, workflowPath := range repo.Workflows {
		// Verificar que el cliente no sea nil antes de usarlo
		if wa.client == nil {
			log.Printf("  Error: Cliente GitHub es nil para %s", workflowPath)
			continue
		}

		// Obtener contenido del archivo de workflow
		workflowContent, err := wa.client.GetContents(repo.Owner, repo.Name, workflowPath)
		if err != nil {
			log.Printf("  Error al obtener contenido de %s: %v", workflowPath, err)
			continue
		}

		// Verificar que el contenido no sea nil
		if workflowContent == nil || len(workflowContent) == 0 {
			log.Printf("  Error: Contenido vacío o nil para %s", workflowPath)
			continue
		}

		// Parsear YAML
		var workflowData map[string]interface{}
		err = yaml.Unmarshal(workflowContent, &workflowData)
		if err != nil {
			log.Printf("  Error al parsear YAML de %s: %v", workflowPath, err)
			continue
		}

		// Analizar vulnerabilidades en el workflow
		analyzer := NewVulnerabilityDetector()
		fileVulns := analyzer.DetectVulnerabilities(workflowPath, string(workflowContent), workflowData)
		vulnerabilities = append(vulnerabilities, fileVulns...)
	}

	return vulnerabilities, nil
}
