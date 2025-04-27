package report

import "github.com/cmalvaceda/tesis-poc/pkg/models"

// Reporter define la interfaz para generadores de reportes
type Reporter interface {
	GenerateReport(vulnerabilities []models.Vulnerability, outputFile string) error
}
