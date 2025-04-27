package analyzer

import (
	"regexp"
	"strings"

	"github.com/cmalvaceda/tesis-poc/pkg/models"
)

// SecretExposureDetector detecta exposición de secretos
type SecretExposureDetector struct{}

// NewSecretExposureDetector crea un nuevo detector de exposición de secretos
func NewSecretExposureDetector() *SecretExposureDetector {
	return &SecretExposureDetector{}
}

// Detect implementa la interfaz Detector
func (d *SecretExposureDetector) Detect(filePath string, lines []string, workflowData map[string]interface{}) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	// Patrones para detectar exposición potencial de secretos
	debugSecretPattern := regexp.MustCompile(`(?i)(echo|print|console\.log|printf|cat).*\$\{\{\s*secrets\.`)
	envSecretPattern := regexp.MustCompile(`env:.*\$\{\{\s*secrets\..*\s*\}\}`)

	// Buscar uso de secrets en logs o debug
	for i, line := range lines {
		// Caso 1: Secretos potencialmente expuestos en comandos de depuración
		if debugSecretPattern.MatchString(line) {
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Type:        string(models.SecretExposure),
				Description: "Posible exposición de secretos en comandos de salida/depuración",
				Severity:    string(models.SeverityHigh),
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
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Type:        string(models.SecretExposure),
				Description: "Secreto expuesto como variable de entorno sin máscara",
				Severity:    string(models.SeverityMedium),
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
