package analyzer

import (
	"strings"

	"github.com/cmalvaceda/tesis-poc/pkg/models"
)

type ScriptInjectionDetector struct{}

func NewScriptInjectionDetector() *ScriptInjectionDetector {
	return &ScriptInjectionDetector{}
}

func (d *ScriptInjectionDetector) Detect(filePath string, lines []string, workflowData map[string]interface{}) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	inScript := false
	scriptContent := ""

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		if strings.HasPrefix(trimmedLine, "run: |") || strings.HasPrefix(trimmedLine, "run:|") {
			inScript = true
			scriptContent = ""
			continue
		}

		if inScript {
			if !strings.HasPrefix(trimmedLine, "-") && !strings.HasPrefix(trimmedLine, "run:") &&
				len(trimmedLine) > 0 && trimmedLine[0] != '#' {
				scriptContent += line + "\n"

				if strings.Contains(line, "${{") && strings.Contains(line, "github.event") &&
					!strings.Contains(line, "\"${{") && !strings.Contains(line, "'${{") {

					if !strings.Contains(line, "github.event.repository") &&
						!strings.Contains(line, "github.event.number") {

						vulnerabilities = append(vulnerabilities, models.Vulnerability{
							Type:        string(models.ScriptInjection),
							Description: "Script multilinea con posible inyección de parámetros no sanitizados",
							Severity:    string(models.SeverityMedium),
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
				inScript = false
			}
		}
	}

	return vulnerabilities
}
