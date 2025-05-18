package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sort"

	"github.com/cmalvaceda/tesis-poc/internal/config"
	"github.com/cmalvaceda/tesis-poc/pkg/github"
	"github.com/cmalvaceda/tesis-poc/pkg/models"
	gh "github.com/google/go-github/v60/github"
)

// Constants for GHAS full flow automation
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
	outputFile := flag.String("o", "repos_workflows_ghas.txt", "Archivo de salida para guardar la lista de repositorios procesados.")
	enableGitleaks := flag.Bool("gitleaks", true, "Activar análisis de secretos con GitLeaks.")
	enableContainerScan := flag.Bool("containerscan", true, "Activar análisis de vulnerabilidades en contenedores Docker.")
	enableAll := flag.Bool("all", false, "Ejecutar la recolección y análisis GHAS para todos los repositorios encontrados.")
	specificRepo := flag.String("repo", "", "Procesar un repositorio específico (formato: 'propietario/nombre').")
	showUserInfo := flag.Bool("userinfo", false, "Mostrar información del usuario autenticado y sus forks.")
	forceUpdate := flag.Bool("force", false, "Forzar la actualización de ramas existentes.")
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
	user, err := client.GetAuthenticatedUserLogin()
	if err != nil {
		log.Fatalf("Error al obtener usuario autenticado: %v", err)
	}
	log.Printf("Autenticado como: %s\n", user)

	// Si se solicita mostrar información del usuario
	if *showUserInfo {
		log.Printf("\n=== INFORMACIÓN DEL USUARIO AUTENTICADO ===\n")
		userDetails, err := client.GetAuthenticatedUser()
		if err != nil {
			log.Fatalf("Error al obtener detalles del usuario: %v", err)
		}

		log.Printf("Nombre: %s\n", userDetails.GetName())
		log.Printf("Login: %s\n", userDetails.GetLogin())
		log.Printf("Email: %s\n", userDetails.GetEmail())
		log.Printf("Bio: %s\n", userDetails.GetBio())
		log.Printf("URL: %s\n", userDetails.GetHTMLURL())
		log.Printf("Repositorios públicos: %d\n", userDetails.GetPublicRepos())

		// Obtener lista de forks del usuario
		repos, err := client.ListUserRepositories()
		if err != nil {
			log.Printf("Error al obtener repositorios del usuario: %v\n", err)
		} else {
			// Filtrar solo los forks
			var forks []*gh.Repository
			for _, repo := range repos {
				if repo.GetFork() {
					forks = append(forks, repo)
				}
			}

			log.Printf("\nForks creados (%d):\n", len(forks))
			for i, fork := range forks {
				log.Printf("%d. %s (creado: %s)\n", i+1, fork.GetFullName(), fork.GetCreatedAt().Format("2006-01-02 15:04:05"))
			}
		}

		log.Printf("\n=== FIN DE INFORMACIÓN DEL USUARIO ===\n")
		return
	}

	var repoWorkflows []models.RepoWorkflows

	// FASE 1: Recolección de repositorios
	if *specificRepo != "" {
		// Procesar un repositorio específico si se proporciona
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

		repoWorkflow := models.RepoWorkflows{
			FullName:      *specificRepo,
			WorkflowFiles: workflowFiles,
		}

		// Add to the collection for processing
		repoWorkflows = append(repoWorkflows, repoWorkflow)

		log.Printf("Repositorio encontrado: %s con %d workflows\n", *specificRepo, len(workflowFiles))
	} else {
		// Búsqueda y recolección de repositorios con workflows
		log.Printf("FASE 1: RECOLECCIÓN - Buscando repositorios con workflows...\n")
		log.Printf("Realizando búsqueda con consulta: '%s'\n", *query)

		collector := github.NewWorkflowCollector(client, maxRepos)
		repoWorkflows, err = collector.CollectWorkflows(*query)
		if err != nil {
			log.Fatalf("Error al buscar repositorios: %v", err)
		}

		log.Printf("Encontrados %d repositorios con workflows para análisis GHAS\n", len(repoWorkflows))

		// Guardar la lista de repositorios y sus workflows en el archivo de salida
		err = models.SaveWorkflowsToFile(repoWorkflows, *outputFile)
		if err != nil {
			log.Fatalf("Error al guardar la lista de repositorios: %v", err)
		}
		log.Printf("Lista de repositorios y workflows guardada en '%s'\n", *outputFile)
	}

	// Si no está activado el modo de análisis completo, terminar aquí
	if !*enableAll && *specificRepo == "" {
		log.Println("Fase de recolección completada. Para realizar el análisis GHAS, use la bandera -all o especifique un repositorio con -repo")
		return
	}

	// FASE 2: Automatización de GHAS - Para cada repositorio recolectado
	log.Printf("\nFASE 2: ANÁLISIS GHAS - Configurando GitHub Advanced Security en cada repositorio...\n")

	processedCount := 0
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

		// Check if we want to limit the number of processed repositories
		if processedCount >= maxRepos {
			log.Printf("Alcanzado el máximo número de repositorios a procesar (%d)\n", maxRepos)
			break
		}
		processedCount++

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
		} // Verificar si ya existe la rama ghas-analysis
		log.Printf("  Verificando si ya existe la rama %s...\n", branchName)

		// Obtener lista de ramas remotas
		output, err := runGitCommandWithOutput(repoDir, "ls-remote", "--heads", "origin")

		// Si la rama existe y no estamos forzando la actualización
		if err == nil && strings.Contains(output, "refs/heads/"+branchName) && !*forceUpdate {
			log.Printf("  La rama %s ya existe en el repositorio remoto.\n", branchName)

			// Hacer checkout de la rama existente
			err = runGitCommand(repoDir, "fetch", "origin", branchName)
			if err != nil {
				log.Printf("  Error al realizar fetch de la rama existente: %v. Saltando.\n", err)
				continue
			}

			err = runGitCommand(repoDir, "checkout", branchName)
			if err != nil {
				log.Printf("  Error al hacer checkout de la rama existente: %v. Saltando.\n", err)
				continue
			}

			// Verificamos si ya tiene configuraciones de GHAS
			codeqlExists := fileExists(filepath.Join(repoDir, ".github", "workflows", "codeql.yml"))
			dependabotExists := fileExists(filepath.Join(repoDir, ".github", "dependabot.yml"))

			if codeqlExists && dependabotExists {
				log.Printf("  El repositorio ya tiene configuraciones de GHAS. Actualizando configuraciones...\n")
			} else {
				log.Printf("  El repositorio tiene la rama pero faltan algunas configuraciones de GHAS. Agregando...\n")
			}
		} else {
			// Si la rama existe y estamos forzando la actualización
			if err == nil && strings.Contains(output, "refs/heads/"+branchName) && *forceUpdate {
				log.Printf("  La rama %s existe pero se ha solicitado forzar actualización.\n", branchName)
				// Eliminamos la rama remota si existe
				err = runGitCommand(repoDir, "push", "origin", "--delete", branchName)
				if err != nil {
					log.Printf("  Advertencia: No se pudo eliminar la rama remota: %v\n", err)
				}
			}

			// Crear una nueva rama
			log.Printf("  Creando nueva rama: %s\n", branchName)
			err = runGitCommand(repoDir, "checkout", "-b", branchName)
			if err != nil {
				log.Printf("  Error al crear rama: %v. Saltando.\n", err)
				continue
			}
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
		// Antes de detectar el lenguaje automáticamente, verificar el contenido del repositorio
		log.Printf("  Analizando lenguajes de programación del repositorio...\n")
		language, detectedLanguages := detectRepositoryLanguages(repoDir)
		if len(detectedLanguages) > 0 {
			log.Printf("  Lenguajes detectados: %s\n", strings.Join(detectedLanguages, ", "))
			log.Printf("  Lenguaje principal seleccionado: %s\n", language)
		} else {
			log.Printf("  No se pudo detectar el lenguaje del repositorio, usando lenguaje del fork: %s\n", fork.Language)
			language = detectPrimaryLanguage(fork)
		}
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
		// Construir URL con token para autenticación
		remoteURL := fmt.Sprintf("https://%s@github.com/%s/%s.git", githubToken, fork.Owner, fork.Name)
		err = runGitCommand(repoDir, "remote", "set-url", "origin", remoteURL)
		if err != nil {
			log.Printf("  Error al configurar URL remota: %v. Saltando.\n", err)
			continue
		}

		// Intentar push normal primero
		err = runGitCommand(repoDir, "push", "origin", branchName)
		if err != nil {
			// Si falla, intentar force-push
			log.Printf("  Push normal falló: %v. Intentando force-push...\n", err)
			err = runGitCommand(repoDir, "push", "--force", "origin", branchName)
			if err != nil {
				log.Printf("  Error al enviar cambios (incluso con force): %v. Saltando.\n", err)
				continue
			}
			log.Printf("  Force-push exitoso.\n")
		}

		// No creamos PRs ya que solo necesitamos el análisis de GHAS en nuestro propio fork
		log.Printf("  La configuración GHAS ha sido aplicada en la rama %s del fork.\n", branchName)
		log.Printf("  Las herramientas de GHAS comenzarán el análisis automáticamente.\n")
		log.Printf("  Los resultados estarán disponibles en la pestaña 'Seguridad' del repositorio.\n")

		// Wait a bit before processing next repository to avoid rate limiting
		if i < len(repoWorkflows)-1 {
			log.Printf("  Esperando unos segundos antes de procesar el siguiente repositorio...\n")
			time.Sleep(3 * time.Second)
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

	log.Printf("\nFLUJO COMPLETO FINALIZADO: %d repositorios procesados\n", processedCount)
	log.Printf("El análisis GHAS se ha configurado correctamente y comenzará automáticamente en los forks creados.\n")
	log.Printf("Los resultados del análisis estarán disponibles en la pestaña 'Seguridad' de cada repositorio fork en GitHub.\n")
}

// addWorkflowFromTemplate reads a template file and creates a workflow file with replacements
func addWorkflowFromTemplate(templatePath, outputPath string, replacements map[string]string) error {
	// Read template content
	content, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("error al leer plantilla %s: %w", templatePath, err)
	}

	// Apply replacements if any
	contentStr := string(content)
	for key, value := range replacements {
		placeholder := fmt.Sprintf("'%s'", key) // Matches 'language' or 'ecosystem' in template

		// Manejo especial para lenguajes en el template de CodeQL
		if key == "language" && strings.Contains(value, ",") {
			// Si hay múltiples lenguajes, los formateamos como lista YAML
			langs := strings.Split(value, ",")
			formattedLangs := ""
			for _, lang := range langs {
				lang = strings.TrimSpace(lang)
				formattedLangs += fmt.Sprintf("\n        - '%s'", lang)
			}
			contentStr = strings.Replace(contentStr, fmt.Sprintf("[ '%s' ]", key), formattedLangs, -1)
		} else {
			// Reemplazo normal para otros casos
			contentStr = strings.Replace(contentStr, placeholder, fmt.Sprintf("'%s'", value), -1)
		}
	}

	// Write the output file
	err = os.WriteFile(outputPath, []byte(contentStr), 0644)
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

// runGitCommandWithOutput runs a git command and returns the output
func runGitCommandWithOutput(dir string, args ...string) (string, error) {
	cmd := models.NewCommand("git", args...)
	if dir != "" {
		cmd.SetDir(dir)
	}
	return cmd.Run()
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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

// detectRepositoryLanguages analiza los archivos en el repositorio para detectar lenguajes de programación
func detectRepositoryLanguages(repoDir string) (string, []string) {
	// Mapeo de extensiones de archivo a lenguajes
	languageMap := map[string]string{
		".go":    "go",
		".js":    "javascript",
		".jsx":   "javascript",
		".ts":    "javascript", // TypeScript se mapea a javascript para CodeQL
		".tsx":   "javascript",
		".py":    "python",
		".java":  "java",
		".kt":    "java", // Kotlin se mapea a java para CodeQL
		".cs":    "csharp",
		".cpp":   "cpp",
		".c":     "cpp",
		".h":     "cpp",
		".hpp":   "cpp",
		".cc":    "cpp",
		".rb":    "ruby",
		".php":   "php",
		".rs":    "rust",
		".swift": "swift",
		".m":     "swift", // Objective-C
	}

	// Contador de archivos por lenguaje
	languageCounts := make(map[string]int)

	// Función para caminar por los directorios
	err := filepath.Walk(repoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Saltar directorios .git y node_modules
		if info.IsDir() && (info.Name() == ".git" || info.Name() == "node_modules" ||
			info.Name() == "vendor" || info.Name() == "dist" || info.Name() == ".github") {
			return filepath.SkipDir
		}

		// Solo procesar archivos
		if !info.IsDir() {
			ext := filepath.Ext(path)
			if lang, ok := languageMap[ext]; ok {
				languageCounts[lang]++
			}
		}
		return nil
	})

	if err != nil {
		return "javascript", nil // Default en caso de error
	}

	// Encuentra el lenguaje más común y lenguajes relevantes
	mostCommon := "javascript" // Default
	maxCount := 0

	var detectedLanguages []string
	var relevantLanguages []string

	// Solo consideramos lenguajes con más de un mínimo de archivos
	minFilesThreshold := 3

	for lang, count := range languageCounts {
		if count > 0 {
			detectedLanguages = append(detectedLanguages, lang)

			// Si el lenguaje tiene suficientes archivos, lo consideramos relevante
			if count >= minFilesThreshold {
				relevantLanguages = append(relevantLanguages, lang)
			}
		}

		if count > maxCount {
			maxCount = count
			mostCommon = lang
		}
	}

	// Ordenar los lenguajes detectados para mostrarlos de manera consistente
	sort.Strings(detectedLanguages)
	sort.Strings(relevantLanguages)

	// Si no se detectó ningún lenguaje, usar javascript como default
	if maxCount == 0 {
		return "javascript", detectedLanguages
	}

	// Si hay múltiples lenguajes relevantes, devolvemos una string con todos separados por comas
	if len(relevantLanguages) > 1 {
		return strings.Join(relevantLanguages, ", "), detectedLanguages
	}

	return mostCommon, detectedLanguages
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
