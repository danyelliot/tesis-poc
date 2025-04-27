package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	gh "github.com/google/go-github/v60/github"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

const (
	defaultOutputFile = "actions_repos_workflows_go.txt"
	baseSearchQuery   = "path:.github/workflows "
	defaultMaxRepos   = 5000
	workflowsDir      = ".github/workflows"
)

type RepoWorkflows struct {
	FullName      string
	WorkflowFiles []string
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Advertencia: No se pudo cargar el archivo .env: %v. Se intentará usar variables de entorno existentes.", err)
	}

	query := flag.String("q", baseSearchQuery, "Consulta de búsqueda de GitHub. Puedes añadir más filtros.")
	outputFile := flag.String("o", defaultOutputFile, "Archivo de salida para guardar la lista de repositorios y sus workflows.")
	maxReposStr := flag.String("m", strconv.Itoa(defaultMaxRepos), "Número máximo de repositorios a procesar.")
	flag.Parse()

	maxRepos, err := strconv.Atoi(*maxReposStr)
	if err != nil || maxRepos <= 0 {
		log.Fatalf("Error: El número máximo de repositorios (-m) debe ser un entero positivo: %v", err)
	}

	githubToken := os.Getenv("GITHUB_PAT")
	if githubToken == "" {
		log.Fatal("Error: Token de GitHub (GITHUB_PAT) no encontrado en las variables de entorno o en el archivo .env.")
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubToken},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := gh.NewClient(tc)

	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		log.Fatalf("Error al autenticar con la API de GitHub: %v", err)
	}
	log.Printf("Autenticado como: %s\n", user.GetLogin())
	log.Printf("Realizando búsqueda con consulta: '%s'\n", *query)

	var allRepoWorkflows []RepoWorkflows
	opts := &gh.SearchOptions{
		Sort:        "indexed",
		Order:       "desc",
		ListOptions: gh.ListOptions{PerPage: 100},
	}

	processedRepoCount := 0
	for {
		if processedRepoCount >= maxRepos {
			log.Printf("Alcanzado el límite máximo de %d repositorios procesados.\n", maxRepos)
			break
		}

		remaining := maxRepos - processedRepoCount
		if remaining < opts.ListOptions.PerPage {
			opts.ListOptions.PerPage = remaining
		}
		if opts.ListOptions.PerPage <= 0 {
			opts.ListOptions.PerPage = 1
		}

		log.Printf("Buscando página %d (hasta %d repositorios por página)...\n", opts.Page, opts.ListOptions.PerPage)
		result, resp, err := client.Search.Repositories(ctx, *query, opts)
		if err != nil {
			if _, ok := err.(*gh.RateLimitError); ok {
				log.Println("Advertencia: Límite de tasa de la API de GitHub excedido. Esperando...")
				time.Sleep(1 * time.Minute)
				continue
			}
			log.Printf("Error al buscar repositorios: %v\n", err)
			break
		}

		log.Printf("API reported %d total results for this query. Response status: %s\n", result.GetTotal(), resp.Status)

		if len(result.Repositories) == 0 {
			if result.GetTotal() > 0 && processedRepoCount < maxRepos {
				log.Println("Advertencia: La página actual está vacía, pero la API reporta más resultados totales. Puede haber un problema con la paginación o la consulta.")
			} else {
				log.Println("No se encontraron más repositorios.")
			}
			break
		}

		for _, repo := range result.Repositories {
			if processedRepoCount >= maxRepos {
				break
			}

			repoName := repo.GetFullName()
			owner := repo.GetOwner().GetLogin()
			repoShortName := repo.GetName()

			log.Printf("Intentando procesar: %s (Encontrados con workflows hasta ahora: %d/%d)\n", repoName, processedRepoCount, maxRepos)

			_, dirContent, _, err := client.Repositories.GetContents(ctx, owner, repoShortName, workflowsDir, nil)
			if err != nil {
				if ghErr, ok := err.(*gh.ErrorResponse); ok && ghErr.Response.StatusCode == 404 {
					log.Printf("  Advertencia: Directorio '%s' no encontrado en %s (puede haber sido eliminado o renombrado después de la indexación). Saltando.\n", workflowsDir, repoName)
				} else {
					log.Printf("  Error al obtener contenido de '%s' para %s: %v. Saltando.\n", workflowsDir, repoName, err)
				}
				time.Sleep(1 * time.Second)
				continue
			}

			var workflowFiles []string
			if dirContent != nil {
				for _, item := range dirContent {
					if item.GetType() == "file" && (strings.HasSuffix(item.GetName(), ".yml") || strings.HasSuffix(item.GetName(), ".yaml")) {
						workflowFiles = append(workflowFiles, item.GetPath())
					}
				}
			}

			if len(workflowFiles) > 0 {
				log.Printf("  Workflows encontrados: %v\n", workflowFiles)
				allRepoWorkflows = append(allRepoWorkflows, RepoWorkflows{
					FullName:      repoName,
					WorkflowFiles: workflowFiles,
				})
				processedRepoCount++
			} else {
				log.Printf("  No se encontraron archivos .yaml/.yml en '%s' para %s. Saltando.\n", workflowsDir, repoName)
			}

			time.Sleep(200 * time.Millisecond)
		}

		if processedRepoCount >= maxRepos {
			log.Printf("Alcanzado el límite máximo de %d repositorios procesados después de procesar la página.\n", maxRepos)
			break
		}

		if resp.NextPage == 0 {
			log.Println("No hay más páginas de resultados de búsqueda.")
			break
		}
		opts.Page = resp.NextPage

		log.Println("Pausa antes de solicitar la siguiente página...")
		time.Sleep(1 * time.Second)
	}

	log.Printf("\nBúsqueda y procesamiento completados. Total de repositorios con workflows encontrados y guardados: %d\n", len(allRepoWorkflows))

	err = saveWorkflowsToFile(allRepoWorkflows, *outputFile)
	if err != nil {
		log.Fatalf("Error al guardar en el archivo: %v", err)
	}
}

func saveWorkflowsToFile(repoWorkflows []RepoWorkflows, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("no se pudo crear el archivo '%s': %w", filename, err)
	}
	defer file.Close()

	var outputLines []string
	for _, rw := range repoWorkflows {
		line := fmt.Sprintf("%s: %s", rw.FullName, strings.Join(rw.WorkflowFiles, ","))
		outputLines = append(outputLines, line)
	}

	_, err = file.WriteString(strings.Join(outputLines, "\n") + "\n")
	if err != nil {
		return fmt.Errorf("no se pudo escribir en el archivo '%s': %w", filename, err)
	}

	log.Printf("Lista de repositorios y sus workflows guardada en '%s'\n", filename)
	return nil
}
