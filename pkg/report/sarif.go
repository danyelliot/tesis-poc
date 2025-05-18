package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cmalvaceda/tesis-poc/pkg/models"
)

type SARIFReporter struct{}

func NewSARIFReporter() *SARIFReporter {
	return &SARIFReporter{}
}

func (sr *SARIFReporter) GenerateReport(vulnerabilities []models.Vulnerability, outputFile string) error {
	uniqueRuleIds := make(map[string]bool)
	var rules []SARIFRule

	for _, vuln := range vulnerabilities {
		ruleID := strings.ReplaceAll(vuln.Type, " ", "")

		if !uniqueRuleIds[ruleID] {
			uniqueRuleIds[ruleID] = true

			var securitySeverity string
			switch vuln.Severity {
			case string(models.SeverityHigh):
				securitySeverity = "8.9"
			case string(models.SeverityMedium):
				securitySeverity = "5.5"
			case string(models.SeverityLow):
				securitySeverity = "3.0"
			default:
				securitySeverity = "1.0"
			}

			rule := SARIFRule{
				ID:   ruleID,
				Name: vuln.Type,
				ShortDescription: SARIFMessage{
					Text: vuln.Description,
				},
				FullDescription: SARIFMessage{
					Text: vuln.Impact,
				},
				Help: SARIFMessage{
					Text: vuln.Mitigation,
				},
				Properties: SARIFRuleProperty{
					SecuritySeverity: securitySeverity,
					Tags:             []string{"security", "github-actions", "ci-cd"},
				},
			}
			rules = append(rules, rule)
		}
	}

	var results []SARIFResult
	for _, vuln := range vulnerabilities {
		ruleID := strings.ReplaceAll(vuln.Type, " ", "")

		level := "warning"
		if vuln.Severity == string(models.SeverityHigh) {
			level = "error"
		} else if vuln.Severity == string(models.SeverityLow) {
			level = "note"
		}

		message := SARIFMessage{
			Text: fmt.Sprintf("%s - %s", vuln.Description, strings.Split(vuln.Details, "\n")[0]),
		}

		result := SARIFResult{
			RuleID:  ruleID,
			Level:   level,
			Message: message,
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: vuln.File,
						},
						Region: SARIFRegion{
							StartLine: vuln.Line,
							Snippet: SARIFSnippet{
								Text: vuln.Details,
							},
						},
					},
				},
			},
		}
		results = append(results, result)
	}

	startTime := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	endTime := time.Now().UTC().Format(time.RFC3339)

	sarifReport := SARIFReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "GitHub Actions Workflow Analyzer",
						Version:        "1.0.0",
						InformationURI: "https://github.com/cmalvaceda/tesis-poc",
						Rules:          rules,
					},
				},
				Results: results,
				Invocations: []SARIFInvocation{
					{
						ExecutionSuccessful: true,
						StartTimeUTC:        startTime,
						EndTimeUTC:          endTime,
					},
				},
			},
		},
	}

	jsonData, err := json.MarshalIndent(sarifReport, "", "  ")
	if err != nil {
		return fmt.Errorf("error al crear JSON SARIF: %w", err)
	}

	err = os.WriteFile(outputFile, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("error al guardar archivo SARIF: %w", err)
	}

	return nil
}

type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription SARIFMessage      `json:"shortDescription"`
	FullDescription  SARIFMessage      `json:"fullDescription"`
	Help             SARIFMessage      `json:"help"`
	Properties       SARIFRuleProperty `json:"properties"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFRuleProperty struct {
	SecuritySeverity string   `json:"security-severity"`
	Tags             []string `json:"tags"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int          `json:"startLine"`
	Snippet   SARIFSnippet `json:"snippet,omitempty"`
}

type SARIFSnippet struct {
	Text string `json:"text"`
}

type SARIFInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUTC        string `json:"startTimeUtc"`
	EndTimeUTC          string `json:"endTimeUtc"`
}
