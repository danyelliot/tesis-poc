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

	"github.com/google/go-github/v60/github"
	"github.com/joho/godotenv" // Import godotenv
	"golang.org/x/oauth2"
)

const (
	defaultOutputFile = "actions_repos_workflows_go.txt"
	baseSearchQuery   = "path:.github/workflows" // REMOVED stars:>10 filter
	defaultMaxRepos   = 5000
	workflowsDir      = ".github/workflows"
)

// Structure to hold repository and its workflow files
type RepoWorkflows struct {
	FullName      string
	WorkflowFiles []string
}

func main() {
	// --- Cargar variables de .env ---
	err := godotenv.Load() // Load .env file first
	if err != nil {
		// Log a warning instead of fatal if .env is optional or might not exist
		log.Printf("Advertencia: No se pudo cargar el archivo .env: %v. Se intentará usar variables de entorno existentes.", err)
	}

	// --- Argumentos de línea de comandos ---
	query := flag.String("q", baseSearchQuery, "Consulta de búsqueda de GitHub. Puedes añadir más filtros.")
	outputFile := flag.String("o", defaultOutputFile, "Archivo de salida para guardar la lista de repositorios y sus workflows.")
	maxReposStr := flag.String("m", strconv.Itoa(defaultMaxRepos), "Número máximo de repositorios a procesar.")
	flag.Parse()

	maxRepos, err := strconv.Atoi(*maxReposStr)
	if err != nil || maxRepos <= 0 {
		log.Fatalf("Error: El número máximo de repositorios (-m) debe ser un entero positivo: %v", err)
	}

	// --- Token de GitHub ---
	// Now os.Getenv will read the value loaded from .env by godotenv
	githubToken := os.Getenv("GITHUB_PAT")
	if githubToken == "" {
		log.Fatal("Error: Token de GitHub (GITHUB_PAT) no encontrado en las variables de entorno o en el archivo .env.")
	}

	// --- Cliente de GitHub ---
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubToken},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	// Verificar autenticación (opcional pero bueno para feedback)
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		log.Fatalf("Error al autenticar con la API de GitHub: %v", err)
	}
	log.Printf("Autenticado como: %s\n", user.GetLogin())
	log.Printf("Realizando búsqueda con consulta: '%s'\n", *query)

	// --- Búsqueda de Repositorios y Workflows ---
	var allRepoWorkflows []RepoWorkflows // Changed from []string to []RepoWorkflows
	opts := &github.SearchOptions{
		Sort:        "indexed",
		Order:       "desc",
		ListOptions: github.ListOptions{PerPage: 100}, // Máximo permitido por página
	}

	processedRepoCount := 0 // Track processed repos separately from search results limit
	for {
		if processedRepoCount >= maxRepos {
			log.Printf("Alcanzado el límite máximo de %d repositorios procesados.\n", maxRepos)
			break
		}

		// Adjust PerPage based on remaining repos to process, not just search limit
		remaining := maxRepos - processedRepoCount
		if remaining < opts.ListOptions.PerPage {
			opts.ListOptions.PerPage = remaining
		}
		if opts.ListOptions.PerPage <= 0 { // Ensure PerPage is positive
			opts.ListOptions.PerPage = 1
		}

		log.Printf("Buscando página %d (hasta %d repositorios por página)...\n", opts.Page, opts.ListOptions.PerPage)
		result, resp, err := client.Search.Repositories(ctx, *query, opts)
		if err != nil {
			// Manejo específico de Rate Limit
			if _, ok := err.(*github.RateLimitError); ok {
				log.Println("Advertencia: Límite de tasa de la API de GitHub excedido. Esperando...")
				// Podrías implementar una espera más sofisticada basada en resp.Rate.Reset
				time.Sleep(1 * time.Minute)
				continue // Reintentar la misma página
			}
			log.Printf("Error al buscar repositorios: %v\n", err)
			// Considerar si continuar o salir en otros errores
			break
		}

		// Log total count reported by API and status code
		log.Printf("API reported %d total results for this query. Response status: %s\n", result.GetTotal(), resp.Status)

		if len(result.Repositories) == 0 {
			// Add a check for total results > 0 even if this page is empty
			if result.GetTotal() > 0 && processedRepoCount < maxRepos {
				log.Println("Advertencia: La página actual está vacía, pero la API reporta más resultados totales. Puede haber un problema con la paginación o la consulta.")
			} else {
				log.Println("No se encontraron más repositorios.")
			}
			break
		}

		// Process repositories found on this page
		for _, repo := range result.Repositories {
			if processedRepoCount >= maxRepos {
				break // Stop processing if max limit reached within the page
			}

			repoName := repo.GetFullName()
			owner := repo.GetOwner().GetLogin()
			repoShortName := repo.GetName()

			// Log processing attempt, but use a different counter for display if needed
			log.Printf("Intentando procesar: %s (Encontrados con workflows hasta ahora: %d/%d)\n", repoName, processedRepoCount, maxRepos)

			// Get workflow files for this repository
			_, dirContent, _, err := client.Repositories.GetContents(ctx, owner, repoShortName, workflowsDir, nil)
			if err != nil {
				// Handle common errors gracefully (e.g., repo deleted, dir not found, permissions)
				if ghErr, ok := err.(*github.ErrorResponse); ok && ghErr.Response.StatusCode == 404 {
					log.Printf("  Advertencia: Directorio '%s' no encontrado en %s (puede haber sido eliminado o renombrado después de la indexación). Saltando.\n", workflowsDir, repoName)
				} else {
					log.Printf("  Error al obtener contenido de '%s' para %s: %v. Saltando.\n", workflowsDir, repoName, err)
				}
				// Optionally sleep longer after an error to avoid hammering
				time.Sleep(1 * time.Second)
				continue // Skip this repo - DO NOT increment processedRepoCount here
			}

			var workflowFiles []string
			if dirContent != nil {
				for _, item := range dirContent {
					if item.GetType() == "file" && (strings.HasSuffix(item.GetName(), ".yml") || strings.HasSuffix(item.GetName(), ".yaml")) {
						workflowFiles = append(workflowFiles, item.GetPath()) // Store full path within repo
					}
				}
			}

			if len(workflowFiles) > 0 {
				log.Printf("  Workflows encontrados: %v\n", workflowFiles)
				allRepoWorkflows = append(allRepoWorkflows, RepoWorkflows{
					FullName:      repoName,
					WorkflowFiles: workflowFiles,
				})
				processedRepoCount++ // Increment only when repo is successfully processed AND has workflows
			} else {
				log.Printf("  No se encontraron archivos .yaml/.yml en '%s' para %s. Saltando.\n", workflowsDir, repoName)
				// DO NOT increment processedRepoCount here either, as no workflows were added.
			}

			// Small delay between GetContents calls
			time.Sleep(200 * time.Millisecond)
		} // End loop through repos on page

		if processedRepoCount >= maxRepos {
			log.Printf("Alcanzado el límite máximo de %d repositorios procesados después de procesar la página.\n", maxRepos)
			break // Exit outer loop if max limit reached
		}

		if resp.NextPage == 0 {
			log.Println("No hay más páginas de resultados de búsqueda.")
			break // No hay más páginas
		}
		opts.Page = resp.NextPage

		// Pause between pages
		log.Println("Pausa antes de solicitar la siguiente página...")
		time.Sleep(1 * time.Second) // Increased sleep between pages due to GetContents calls
	}

	log.Printf("\nBúsqueda y procesamiento completados. Total de repositorios con workflows encontrados y guardados: %d\n", len(allRepoWorkflows))

	// --- Guardar en Archivo ---
	err = saveWorkflowsToFile(allRepoWorkflows, *outputFile) // Use new save function
	if err != nil {
		log.Fatalf("Error al guardar en el archivo: %v", err)
	}
}

// Updated function to save repo name and its workflow files
func saveWorkflowsToFile(repoWorkflows []RepoWorkflows, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("no se pudo crear el archivo '%s': %w", filename, err)
	}
	defer file.Close()

	var outputLines []string
	for _, rw := range repoWorkflows {
		// Format: repoFullName: workflowPath1,workflowPath2,...
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
