package analyzer

import (
	"regexp"
	"strings"

	"github.com/cmalvaceda/tesis-poc/pkg/models"
)

type UnsafeActionsDetector struct{}

func NewUnsafeActionsDetector() *UnsafeActionsDetector {
	return &UnsafeActionsDetector{}
}

func (d *UnsafeActionsDetector) Detect(filePath string, lines []string, workflowData map[string]interface{}) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	actionWithoutVersionPattern := regexp.MustCompile(`uses:\s+[^@]+$`)
	actionWithBranchPattern := regexp.MustCompile(`uses:\s+[^@]+@\s*(main|master|develop|dev)`)

	fullSHAPattern := regexp.MustCompile(`uses:\s+[^@]+@[0-9a-f]{40}`)

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "uses:") {
			if fullSHAPattern.MatchString(trimmedLine) {
				continue
			}

			if actionWithoutVersionPattern.MatchString(trimmedLine) {
				vulnerabilities = append(vulnerabilities, models.Vulnerability{
					Type:        string(models.UnsafeActionReference),
					Description: "Acción referenciada sin versión específica",
					Severity:    string(models.SeverityMedium),
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

			if actionWithBranchPattern.MatchString(trimmedLine) {
				vulnerabilities = append(vulnerabilities, models.Vulnerability{
					Type:        string(models.UnsafeActionReference),
					Description: "Acción referenciada usando una rama en lugar de una versión fija",
					Severity:    string(models.SeverityHigh),
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
