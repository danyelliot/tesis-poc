package github

import (
	"context"
	"fmt"

	gh "github.com/google/go-github/v60/github"
	"golang.org/x/oauth2"
)

const (
	DefaultSearchQuery = "path:.github/workflows"
	WorkflowsDir       = ".github/workflows"
)

// Client encapsula el cliente de GitHub y su contexto
type Client struct {
	client *gh.Client
	ctx    context.Context
}

// NewClient crea un nuevo cliente de GitHub
func NewClient(token string) (*Client, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := gh.NewClient(tc)

	// Verificar autenticación
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("error al autenticar con la API de GitHub: %w", err)
	}

	fmt.Printf("Autenticado como: %s\n", user.GetLogin())
	return &Client{
		client: client,
		ctx:    ctx,
	}, nil
}

// GetContents obtiene el contenido de un archivo en un repositorio
func (c *Client) GetContents(owner, repo, path string) ([]byte, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("cliente GitHub no inicializado")
	}

	// Obtener contenido con manejo de posibles errores
	content, _, _, err := c.client.Repositories.GetContents(
		c.ctx,
		owner,
		repo,
		path,
		nil,
	)

	if err != nil {
		return nil, err
	}

	// Verificar que content no sea nil antes de obtener el contenido
	if content == nil {
		return nil, fmt.Errorf("contenido recibido es nil para %s/%s/%s", owner, repo, path)
	}

	// Intenta obtener el contenido con protección contra nil
	decodedContent, err := content.GetContent()
	if err != nil {
		return nil, fmt.Errorf("error al decodificar contenido: %w", err)
	}

	if decodedContent == "" {
		return nil, fmt.Errorf("contenido decodificado está vacío")
	}

	return []byte(decodedContent), nil
}

// ListDirectoryContents lista los contenidos de un directorio en un repositorio
func (c *Client) ListDirectoryContents(owner, repo, path string) ([]*gh.RepositoryContent, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("cliente GitHub no inicializado")
	}

	_, contents, _, err := c.client.Repositories.GetContents(
		c.ctx,
		owner,
		repo,
		path,
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Verificar que contents no sea nil
	if contents == nil {
		return nil, fmt.Errorf("directorio vacío o contenido nil para %s/%s/%s", owner, repo, path)
	}

	return contents, nil
}

// SearchRepositories busca repositorios en GitHub
func (c *Client) SearchRepositories(query string, page, perPage int) (*gh.RepositoriesSearchResult, *gh.Response, error) {
	if c == nil || c.client == nil {
		return nil, nil, fmt.Errorf("cliente GitHub no inicializado")
	}

	opts := &gh.SearchOptions{
		Sort:        "indexed",
		Order:       "desc",
		ListOptions: gh.ListOptions{Page: page, PerPage: perPage},
	}
	return c.client.Search.Repositories(c.ctx, query, opts)
}
