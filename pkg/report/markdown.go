package report

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cmalvaceda/tesis-poc/pkg/models"
)

// MarkdownReporter genera reportes en formato Markdown
type MarkdownReporter struct{}

// NewMarkdownReporter crea un nuevo generador de reportes Markdown
func NewMarkdownReporter() *MarkdownReporter {
	return &MarkdownReporter{}
}

// GenerateReport implementa la interfaz Reporter
func (mr *MarkdownReporter) GenerateReport(vulnerabilities []models.Vulnerability, outputFile string) error {
	file, err := os.Create(outputFile)
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
	vulnerabilityTypes := make(map[string][]models.Vulnerability)
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
