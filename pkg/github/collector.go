package github

import (
	"log"
	"strings"
	"time"

	"github.com/cmalvaceda/tesis-poc/pkg/models"
	gh "github.com/google/go-github/v60/github"
)

type WorkflowCollector struct {
	client   *Client
	maxRepos int
}

func NewWorkflowCollector(client *Client, maxRepos int) *WorkflowCollector {
	return &WorkflowCollector{
		client:   client,
		maxRepos: maxRepos,
	}
}

func (wc *WorkflowCollector) CollectWorkflows(query string) ([]models.RepoWorkflows, error) {
	var allRepoWorkflows []models.RepoWorkflows
	processedRepoCount := 0
	page := 1
	perPage := 100

	for processedRepoCount < wc.maxRepos {
		remaining := wc.maxRepos - processedRepoCount
		if remaining < perPage {
			perPage = remaining
		}

		log.Printf("Buscando página %d (hasta %d repositorios por página)...", page, perPage)
		result, resp, err := wc.client.SearchRepositories(query, page, perPage)

		if err != nil {
			if _, ok := err.(*gh.RateLimitError); ok {
				log.Println("Advertencia: Límite de tasa de la API de GitHub excedido. Esperando...")
				time.Sleep(1 * time.Minute)
				continue
			}
			return nil, err
		}

		if len(result.Repositories) == 0 {
			if result.GetTotal() > 0 && processedRepoCount < wc.maxRepos {
				log.Println("Advertencia: La página actual está vacía, pero la API reporta más resultados totales.")
			} else {
				log.Println("No se encontraron más repositorios.")
			}
			break
		}

		for _, repo := range result.Repositories {
			if processedRepoCount >= wc.maxRepos {
				break
			}

			repoName := repo.GetFullName()
			owner := repo.GetOwner().GetLogin()
			repoShortName := repo.GetName()

			log.Printf("Procesando: %s", repoName)

			dirContent, err := wc.client.ListDirectoryContents(owner, repoShortName, WorkflowsDir)
			if err != nil {
				log.Printf("  Error al obtener workflows para %s: %v. Saltando.", repoName, err)
				time.Sleep(1 * time.Second)
				continue
			}

			var workflowFiles []string
			for _, item := range dirContent {
				if isWorkflowFile(item.GetName()) {
					workflowFiles = append(workflowFiles, item.GetPath())
				}
			}

			if len(workflowFiles) > 0 {
				log.Printf("  Se encontraron %d workflows", len(workflowFiles))
				allRepoWorkflows = append(allRepoWorkflows, models.RepoWorkflows{
					FullName:      repoName,
					WorkflowFiles: workflowFiles,
				})
				processedRepoCount++
			} else {
				log.Printf("  No se encontraron workflows. Saltando.")
			}

			time.Sleep(200 * time.Millisecond)
		}

		if resp.NextPage == 0 {
			log.Println("No hay más páginas de resultados.")
			break
		}

		page = resp.NextPage
		time.Sleep(1 * time.Second)
	}

	return allRepoWorkflows, nil
}

func isWorkflowFile(filename string) bool {
	return strings.HasSuffix(filename, ".yml") || strings.HasSuffix(filename, ".yaml")
}
