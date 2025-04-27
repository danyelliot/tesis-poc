package models

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

// RepoInfo contiene información básica de un repositorio
type RepoInfo struct {
	Owner     string
	Name      string
	FullName  string
	Workflows []string
}

// RepoWorkflows representa un repositorio con sus archivos de workflow
type RepoWorkflows struct {
	FullName      string
	WorkflowFiles []string
}

// ReadRepoWorkflows lee la lista de repositorios y workflows desde un archivo
func ReadRepoWorkflows(filename string) ([]RepoInfo, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("no se pudo abrir el archivo: %w", err)
	}
	defer file.Close()

	var repos []RepoInfo
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			log.Printf("Advertencia: Línea con formato incorrecto: %s", line)
			continue
		}

		fullName := parts[0]
		workflows := strings.Split(parts[1], ",")

		// Extraer owner y nombre del repositorio
		nameParts := strings.SplitN(fullName, "/", 2)
		if len(nameParts) != 2 {
			log.Printf("Advertencia: Nombre de repositorio incorrecto: %s", fullName)
			continue
		}

		repos = append(repos, RepoInfo{
			Owner:     nameParts[0],
			Name:      nameParts[1],
			FullName:  fullName,
			Workflows: workflows,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error al leer el archivo: %w", err)
	}

	return repos, nil
}

// SaveWorkflowsToFile guarda la lista de repositorios y workflows en un archivo
func SaveWorkflowsToFile(repoWorkflows []RepoWorkflows, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("no se pudo crear el archivo '%s': %w", filename, err)
	}
	defer file.Close()

	var outputLines []string
	for _, rw := range repoWorkflows {
		// Format: repoFullName: workflowPath1,workflowPath2,...
		line := fmt.Sprintf("%s: %s", rw.FullName, strings.Join(rw.WorkflowFiles, ","))
		outputLines = append(outputLines, line)
	}

	_, err = file.WriteString(strings.Join(outputLines, "\n") + "\n")
	if err != nil {
		return fmt.Errorf("no se pudo escribir en el archivo '%s': %w", filename, err)
	}

	log.Printf("Lista de repositorios y sus workflows guardada en '%s'\n", filename)
	return nil
}
