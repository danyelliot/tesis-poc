// filepath: /Users/work_profile/tesis-poc/cmd/ghasautomation/main.go
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cmalvaceda/tesis-poc/internal/config"
	"github.com/cmalvaceda/tesis-poc/pkg/github"
	"github.com/cmalvaceda/tesis-poc/pkg/models"
)

// Constants for GHAS automation
const (
	defaultMaxRepos = 10
	branchName      = "ghas-analysis"
	tempDirPrefix   = "ghas-analysis-"
)

// Paths to template files
const (
	templateCodeQL        = "internal/templates/codeql.yml"
	templateDependabot    = "internal/templates/dependabot.yml"
	templateGitleaks      = "internal/templates/gitleaks.yml"
	templateContainerScan = "internal/templates/container-scan.yml"
)

func main() {
	// Load configuration
	_, err := config.LoadConfig()
	if err != nil {
		log.Printf("Advertencia: %v", err)
	}

	// Parse command line flags
	query := flag.String("q", github.DefaultSearchQuery, "Consulta de búsqueda de GitHub para encontrar repositorios con workflows.")
	maxReposStr := flag.String("m", strconv.Itoa(defaultMaxRepos), "Número máximo de repositorios a procesar.")
	cleanupForks := flag.Bool("cleanup", false, "Eliminar forks después del análisis.")
	tempDir := flag.String("tempdir", "", "Directorio temporal para clonar repositorios.")
	enableGitleaks := flag.Bool("gitleaks", true, "Activar análisis de secretos con GitLeaks.")
	enableContainerScan := flag.Bool("containerscan", true, "Activar análisis de vulnerabilidades en contenedores Docker.")
	singleRepo := flag.Bool("single", false, "Procesar solo el primer repositorio encontrado.")
	specificRepo := flag.String("repo", "", "Procesar un repositorio específico (formato: 'propietario/nombre').")
	flag.Parse()

	// Validate max repos
	maxRepos, err := strconv.Atoi(*maxReposStr)
	if err != nil || maxRepos <= 0 {
		log.Fatalf("Error: El número máximo de repositorios (-m) debe ser un entero positivo: %v", err)
	}

	// Validate GitHub token
	githubToken := os.Getenv("GITHUB_PAT")
	if githubToken == "" {
		log.Fatal("Error: Token de GitHub (GITHUB_PAT) no encontrado en las variables de entorno.")
	}

	// Create temporary directory if not specified
	workDir := *tempDir
	if workDir == "" {
		workDir, err = os.MkdirTemp("", tempDirPrefix)
		if err != nil {
			log.Fatalf("Error al crear directorio temporal: %v", err)
		}
		defer os.RemoveAll(workDir)
	}

	// Initialize GitHub client
	client, err := github.NewClient(githubToken)
	if err != nil {
		log.Fatalf("Error al crear cliente de GitHub: %v", err)
	}

	// Get authenticated user
	user, err := client.GetAuthenticatedUser()
	if err != nil {
		log.Fatalf("Error al obtener usuario autenticado: %v", err)
	}
	log.Printf("Autenticado como: %s\n", user)

	var repoWorkflows []models.RepoWorkflows
	var repoToProcess *models.RepoWorkflows

	// If a specific repository is provided, create a single workflow item for it
	if *specificRepo != "" {
		parts := strings.Split(*specificRepo, "/")
		if len(parts) != 2 {
			log.Fatalf("El formato del repositorio debe ser 'propietario/nombre', recibido: %s", *specificRepo)
		}

		owner, repoName := parts[0], parts[1]
		log.Printf("Verificando repositorio específico: %s/%s\n", owner, repoName)

		// Verify the repository exists and get its workflow files
		workflowFiles, err := getRepositoryWorkflows(client, owner, repoName)
		if err != nil {
			log.Fatalf("Error al obtener información del repositorio %s/%s: %v", owner, repoName, err)
		}

		repoToProcess = &models.RepoWorkflows{
			FullName:      *specificRepo,
			WorkflowFiles: workflowFiles,
		}

		// Add to the collection for consistent processing
		repoWorkflows = append(repoWorkflows, *repoToProcess)

		log.Printf("Repositorio encontrado: %s con %d workflows\n", *specificRepo, len(workflowFiles))
	} else {
		// Search for repositories with GitHub Actions workflows
		log.Printf("Realizando búsqueda con consulta: '%s'\n", *query)
		collector := github.NewWorkflowCollector(client, maxRepos)
		repoWorkflows, err = collector.CollectWorkflows(*query)
		if err != nil {
			log.Fatalf("Error al buscar repositorios: %v", err)
		}

		log.Printf("Encontrados %d repositorios con workflows para análisis GHAS\n", len(repoWorkflows))

		// If single mode is activated, select only the first repository
		if *singleRepo && len(repoWorkflows) > 0 {
			repoToProcess = &repoWorkflows[0]
			log.Printf("Modo de repositorio único activado. Seleccionando: %s\n", repoToProcess.FullName)
			repoWorkflows = []models.RepoWorkflows{*repoToProcess}
		}
	}

	// Process each repository for GHAS automation
	for i, repo := range repoWorkflows {
		log.Printf("[%d/%d] Procesando repositorio: %s\n", i+1, len(repoWorkflows), repo.FullName)

		// Split the full name into owner and repo
		parts := strings.Split(repo.FullName, "/")
		if len(parts) != 2 {
			log.Printf("  Error: Formato de nombre de repositorio inválido: %s. Saltando.\n", repo.FullName)
			continue
		}

		owner := parts[0]
		repoName := parts[1]

		// Fork the repository
		log.Printf("  Creando fork del repositorio...\n")
		fork, err := client.ForkRepository(owner, repoName)
		if err != nil {
			log.Printf("  Error al crear fork del repositorio: %v. Saltando.\n", err)
			continue
		}

		// Clone the forked repository
		repoDir := filepath.Join(workDir, repoName)
		log.Printf("  Clonando fork a: %s\n", repoDir)
		err = runGitCommand("", "clone", fork.CloneURL, repoDir)
		if err != nil {
			log.Printf("  Error al clonar repositorio: %v. Saltando.\n", err)
			continue
		}

		// Create a new branch
		log.Printf("  Creando rama: %s\n", branchName)
		err = runGitCommand(repoDir, "checkout", "-b", branchName)
		if err != nil {
			log.Printf("  Error al crear rama: %v. Saltando.\n", err)
			continue
		}

		// Configure Git for the commit
		err = runGitCommand(repoDir, "config", "user.name", "GHAS Automation")
		if err != nil {
			log.Printf("  Error al configurar Git: %v. Saltando.\n", err)
			continue
		}

		err = runGitCommand(repoDir, "config", "user.email", "ghas-automation@example.com")
		if err != nil {
			log.Printf("  Error al configurar Git: %v. Saltando.\n", err)
			continue
		}

		// Determine primary language and package ecosystem
		language := detectPrimaryLanguage(fork)
		ecosystem := mapLanguageToEcosystem(language)

		// Create GitHub Actions workflows directory if it doesn't exist
		workflowsDir := filepath.Join(repoDir, ".github", "workflows")
		err = os.MkdirAll(workflowsDir, 0755)
		if err != nil {
			log.Printf("  Error al crear directorio de workflows: %v. Saltando.\n", err)
			continue
		}

		// Create GitHub directory for Dependabot if it doesn't exist
		githubDir := filepath.Join(repoDir, ".github")
		err = os.MkdirAll(githubDir, 0755)
		if err != nil {
			log.Printf("  Error al crear directorio .github: %v. Saltando.\n", err)
			continue
		}

		// Add CodeQL Analysis workflow
		log.Printf("  Agregando workflow de análisis CodeQL...\n")
		if err := addWorkflowFromTemplate(templateCodeQL, filepath.Join(workflowsDir, "codeql.yml"), map[string]string{
			"language": language,
		}); err != nil {
			log.Printf("  Error al crear archivo de workflow CodeQL: %v. Saltando.\n", err)
			continue
		}

		// Add Dependabot configuration
		log.Printf("  Agregando configuración de Dependabot...\n")
		if err := addWorkflowFromTemplate(templateDependabot, filepath.Join(githubDir, "dependabot.yml"), map[string]string{
			"ecosystem": ecosystem,
		}); err != nil {
			log.Printf("  Error al crear archivo de configuración de Dependabot: %v. Saltando.\n", err)
			continue
		}

		// Add GitLeaks secret scanning workflow if enabled
		if *enableGitleaks {
			log.Printf("  Agregando workflow de análisis de secretos GitLeaks...\n")
			if err := addWorkflowFromTemplate(templateGitleaks, filepath.Join(workflowsDir, "gitleaks.yml"), nil); err != nil {
				log.Printf("  Error al crear archivo de workflow GitLeaks: %v\n", err)
			}
		}

		// Add Container scanning workflow if enabled
		if *enableContainerScan {
			log.Printf("  Agregando workflow de análisis de contenedores Docker...\n")
			if err := addWorkflowFromTemplate(templateContainerScan, filepath.Join(workflowsDir, "container-scan.yml"), nil); err != nil {
				log.Printf("  Error al crear archivo de workflow de análisis de contenedores: %v\n", err)
			}
		}

		// Add files, commit, and push changes
		log.Printf("  Creando commit con configuración GHAS...\n")
		err = runGitCommand(repoDir, "add", ".")
		if err != nil {
			log.Printf("  Error al agregar archivos: %v. Saltando.\n", err)
			continue
		}

		err = runGitCommand(repoDir, "commit", "-m", "Add GitHub Advanced Security configuration")
		if err != nil {
			log.Printf("  Error al crear commit: %v. Saltando.\n", err)
			continue
		}

		log.Printf("  Enviando cambios a GitHub...\n")
		err = runGitCommand(repoDir, "push", "origin", branchName)
		if err != nil {
			log.Printf("  Error al enviar cambios: %v. Saltando.\n", err)
			continue
		}

		// Create pull request
		log.Printf("  Creando Pull Request...\n")
		prTitle := "Add GitHub Advanced Security configuration"
		prBody := "Este PR añade configuraciones de GitHub Advanced Security, incluyendo análisis con CodeQL y escaneo de dependencias con Dependabot."
		if *enableGitleaks {
			prBody += " También incluye análisis de secretos con GitLeaks."
		}
		if *enableContainerScan {
			prBody += " Además, se ha añadido un análisis de vulnerabilidades en contenedores Docker."
		}

		_, err = client.CreatePullRequest(fork.Owner, fork.Name, branchName, fork.DefaultBranch, prTitle, prBody)
		if err != nil {
			log.Printf("  Error al crear Pull Request: %v\n", err)
		} else {
			log.Printf("  Pull Request creado exitosamente\n")
		}

		// Clean up fork if requested
		if *cleanupForks {
			log.Printf("  Limpiando fork de %s\n", repo.FullName)
			err = client.DeleteRepository(fork.Owner, fork.Name)
			if err != nil {
				log.Printf("  Error al eliminar fork: %v\n", err)
			}
		}

		log.Printf("  Procesamiento de %s completado\n", repo.FullName)
	}

	log.Printf("\nProceso de automatización GHAS completado para %d repositorios\n", len(repoWorkflows))
}

// addWorkflowFromTemplate reads a template file and creates a workflow file with replacements
func addWorkflowFromTemplate(templatePath, outputPath string, replacements map[string]string) error {
	// Read template content
	content, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("error al leer plantilla %s: %w", templatePath, err)
	}

	// Apply replacements if any
	contentStr := string(content)
	if replacements != nil {
		for key, value := range replacements {
			placeholder := fmt.Sprintf("'%s'", key) // Matches 'language' or 'ecosystem' in template
			contentStr = strings.Replace(contentStr, placeholder, fmt.Sprintf("'%s'", value), -1)
		}
	}

	// Write the output file
	err = ioutil.WriteFile(outputPath, []byte(contentStr), 0644)
	if err != nil {
		return fmt.Errorf("error al escribir en %s: %w", outputPath, err)
	}

	return nil
}

// runGitCommand runs a git command in the specified directory
func runGitCommand(dir string, args ...string) error {
	cmd := models.NewCommand("git", args...)
	if dir != "" {
		cmd.SetDir(dir)
	}
	_, err := cmd.Run()
	return err
}

// detectPrimaryLanguage determines the primary programming language for a repository
func detectPrimaryLanguage(repo *models.Repository) string {
	language := strings.ToLower(repo.Language)

	// Map GitHub repository language to CodeQL language
	switch language {
	case "go", "golang":
		return "go"
	case "javascript", "typescript", "jsx", "tsx":
		return "javascript"
	case "python":
		return "python"
	case "java", "kotlin":
		return "java"
	case "c#", "csharp":
		return "csharp"
	case "c", "c++", "cpp":
		return "cpp"
	case "ruby":
		return "ruby"
	default:
		return "javascript" // Default to JavaScript as it's widely supported
	}
}

// mapLanguageToEcosystem maps a programming language to a package ecosystem for Dependabot
func mapLanguageToEcosystem(language string) string {
	language = strings.ToLower(language)

	// Map language to package ecosystem for Dependabot
	switch language {
	case "go", "golang":
		return "gomod"
	case "javascript", "typescript", "jsx", "tsx":
		return "npm"
	case "python":
		return "pip"
	case "java", "kotlin":
		return "maven"
	case "c#", "csharp":
		return "nuget"
	case "ruby":
		return "bundler"
	case "php":
		return "composer"
	case "rust":
		return "cargo"
	default:
		return "npm" // Default to npm as it's widely used
	}
}

// getRepositoryWorkflows obtiene la lista de archivos de workflow para un repositorio específico
func getRepositoryWorkflows(client *github.Client, owner, repoName string) ([]string, error) {
	// Intenta obtener el contenido del directorio de workflows
	contents, err := client.ListDirectoryContents(owner, repoName, github.WorkflowsDir)
	if err != nil {
		return nil, fmt.Errorf("error al obtener contenido del directorio de workflows: %w", err)
	}

	var workflowFiles []string
	for _, item := range contents {
		if item.GetType() == "file" && (strings.HasSuffix(item.GetName(), ".yml") || strings.HasSuffix(item.GetName(), ".yaml")) {
			workflowFiles = append(workflowFiles, item.GetPath())
		}
	}

	if len(workflowFiles) == 0 {
		return nil, fmt.Errorf("no se encontraron archivos de workflow en el repositorio")
	}

	return workflowFiles, nil
}
