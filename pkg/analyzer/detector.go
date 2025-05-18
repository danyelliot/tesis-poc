package analyzer

import (
	"strings"

	"github.com/cmalvaceda/tesis-poc/pkg/models"
)

type VulnerabilityDetector struct {
	detectors []Detector
}

type Detector interface {
	Detect(filePath string, lines []string, workflowData map[string]interface{}) []models.Vulnerability
}

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

func (vd *VulnerabilityDetector) DetectVulnerabilities(filePath, content string, workflowData map[string]interface{}) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	lines := strings.Split(content, "\n")

	for _, detector := range vd.detectors {
		detectorVulns := detector.Detect(filePath, lines, workflowData)
		vulnerabilities = append(vulnerabilities, detectorVulns...)
	}

	return vulnerabilities
}
