package report

import "github.com/cmalvaceda/tesis-poc/pkg/models"

type Reporter interface {
	GenerateReport(vulnerabilities []models.Vulnerability, outputFile string) error
}
