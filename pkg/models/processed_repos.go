package models

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ProcessedRepository representa información sobre un repositorio ya procesado
type ProcessedRepository struct {
	FullName    string    `json:"full_name"`
	ProcessedAt time.Time `json:"processed_at"`
	Success     bool      `json:"success"`
	Message     string    `json:"message,omitempty"`
}

// ProcessedRepositories mantiene un registro de repositorios ya procesados
type ProcessedRepositories struct {
	Repositories map[string]ProcessedRepository `json:"repositories"`
	lock         sync.RWMutex
	filePath     string
}

// NewProcessedRepositories crea una nueva instancia de ProcessedRepositories
func NewProcessedRepositories(filePath string) (*ProcessedRepositories, error) {
	pr := &ProcessedRepositories{
		Repositories: make(map[string]ProcessedRepository),
		filePath:     filePath,
	}

	// Intentar cargar datos existentes
	err := pr.Load()
	if err != nil && !os.IsNotExist(err) {
		return pr, fmt.Errorf("error al cargar repositorios procesados: %w", err)
	}

	return pr, nil
}

// IsProcessed verifica si un repositorio ya ha sido procesado
func (pr *ProcessedRepositories) IsProcessed(fullName string) bool {
	pr.lock.RLock()
	defer pr.lock.RUnlock()
	_, exists := pr.Repositories[fullName]
	return exists
}

// MarkAsProcessed marca un repositorio como procesado
func (pr *ProcessedRepositories) MarkAsProcessed(fullName string, success bool, message string) error {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	pr.Repositories[fullName] = ProcessedRepository{
		FullName:    fullName,
		ProcessedAt: time.Now(),
		Success:     success,
		Message:     message,
	}

	return pr.Save()
}

// GetProcessed obtiene información de un repositorio procesado
func (pr *ProcessedRepositories) GetProcessed(fullName string) (ProcessedRepository, bool) {
	pr.lock.RLock()
	defer pr.lock.RUnlock()
	repo, exists := pr.Repositories[fullName]
	return repo, exists
}

// GetAllProcessed retorna todos los repositorios procesados
func (pr *ProcessedRepositories) GetAllProcessed() []ProcessedRepository {
	pr.lock.RLock()
	defer pr.lock.RUnlock()

	repos := make([]ProcessedRepository, 0, len(pr.Repositories))
	for _, repo := range pr.Repositories {
		repos = append(repos, repo)
	}

	return repos
}

// Load carga los datos de repositorios procesados desde el archivo
func (pr *ProcessedRepositories) Load() error {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	data, err := os.ReadFile(pr.filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &pr.Repositories)
}

// Save guarda los datos de repositorios procesados en el archivo
func (pr *ProcessedRepositories) Save() error {
	data, err := json.MarshalIndent(pr.Repositories, "", "  ")
	if err != nil {
		return fmt.Errorf("error al serializar repositorios procesados: %w", err)
	}

	return os.WriteFile(pr.filePath, data, 0644)
}

// Count retorna el número de repositorios procesados
func (pr *ProcessedRepositories) Count() int {
	pr.lock.RLock()
	defer pr.lock.RUnlock()
	return len(pr.Repositories)
}
