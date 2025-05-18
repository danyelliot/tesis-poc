package analyzer

import (
	"strings"

	"regexp"

	"github.com/cmalvaceda/tesis-poc/pkg/models"
)

type ExcessivePermissionsDetector struct{}

func NewExcessivePermissionsDetector() *ExcessivePermissionsDetector {
	return &ExcessivePermissionsDetector{}
}

func (d *ExcessivePermissionsDetector) Detect(filePath string, lines []string, workflowData map[string]interface{}) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	if permissions, ok := workflowData["permissions"].(map[string]interface{}); ok {
		if writeAll, ok := permissions["contents"].(string); ok && writeAll == "write" {
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Type:        string(models.ExcessivePermissions),
				Description: "El workflow tiene permisos de escritura completos sobre el repositorio",
				Severity:    string(models.SeverityMedium),
				File:        filePath,
				Line:         0,
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

		if adminLevel, ok := permissions["contents"].(string); ok && adminLevel == "admin" {
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Type:        string(models.ExcessivePermissions),
				Description: "El workflow tiene permisos de administrador",
				Severity:    string(models.SeverityHigh),
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
		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			Type:        string(models.UndefinedPermissions),
			Description: "Workflow sin permisos explícitamente definidos",
			Severity:    string(models.SeverityLow),
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

	tokenWithPermissionsPattern := regexp.MustCompile(`token:\s*\$\{\{\s*secrets\.GITHUB_TOKEN\s*\}\}`)

	for i, line := range lines {
		if tokenWithPermissionsPattern.MatchString(line) {
			hasExplicitPermissions := false

			for j := max(0, i-10); j < min(len(lines), i+10); j++ {
				if strings.Contains(lines[j], "permissions:") {
					hasExplicitPermissions = true
					break
				}
			}

			if !hasExplicitPermissions {
				vulnerabilities = append(vulnerabilities, models.Vulnerability{
					Type:        string(models.UndefinedTokenPermissions),
					Description: "Uso de GITHUB_TOKEN sin permisos explícitamente definidos",
					Severity:    string(models.SeverityLow),
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
