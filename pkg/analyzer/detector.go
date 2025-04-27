package analyzer

import (
	"strings"

	"github.com/cmalvaceda/tesis-poc/pkg/models"
)

// VulnerabilityDetector detecta vulnerabilidades en workflows
type VulnerabilityDetector struct {
	detectors []Detector
}

// Detector define la interfaz para detectores específicos
type Detector interface {
	Detect(filePath string, lines []string, workflowData map[string]interface{}) []models.Vulnerability
}

// NewVulnerabilityDetector crea un nuevo detector con todos los detectores específicos
func NewVulnerabilityDetector() *VulnerabilityDetector {
	return &VulnerabilityDetector{
		detectors: []Detector{
			NewCommandInjectionDetector(),
			NewUnsafeActionsDetector(),
			NewSecretExposureDetector(),
			NewExcessivePermissionsDetector(),
			NewPullRequestTargetDetector(),
			NewScriptInjectionDetector(),
		},
	}
}

// DetectVulnerabilities detecta vulnerabilidades en un workflow
func (vd *VulnerabilityDetector) DetectVulnerabilities(filePath, content string, workflowData map[string]interface{}) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	// Dividir el contenido en líneas para referencia
	lines := strings.Split(content, "\n")

	// Aplicar cada detector
	for _, detector := range vd.detectors {
		detectorVulns := detector.Detect(filePath, lines, workflowData)
		vulnerabilities = append(vulnerabilities, detectorVulns...)
	}

	return vulnerabilities
}
