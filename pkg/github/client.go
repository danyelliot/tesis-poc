package github

import (
	"context"
	"fmt"

	"github.com/cmalvaceda/tesis-poc/pkg/models"
	gh "github.com/google/go-github/v60/github"
	"golang.org/x/oauth2"
)

const (
	DefaultSearchQuery = "path:.github/workflows"
	WorkflowsDir       = ".github/workflows"
)

type Client struct {
	client *gh.Client
	ctx    context.Context
}

func NewClient(token string) (*Client, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := gh.NewClient(tc)

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

// GetAuthenticatedUser retorna información detallada sobre el usuario autenticado
func (c *Client) GetAuthenticatedUser() (*gh.User, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("cliente GitHub no inicializado")
	}

	user, _, err := c.client.Users.Get(c.ctx, "")
	if err != nil {
		return nil, fmt.Errorf("error al obtener información del usuario: %w", err)
	}

	return user, nil
}

// ListUserRepositories lista todos los repositorios del usuario autenticado
func (c *Client) ListUserRepositories() ([]*gh.Repository, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("cliente GitHub no inicializado")
	}

	opt := &gh.RepositoryListOptions{
		Sort: "updated",
		ListOptions: gh.ListOptions{
			PerPage: 100,
		},
	}

	var allRepos []*gh.Repository
	for {
		repos, resp, err := c.client.Repositories.List(c.ctx, "", opt)
		if err != nil {
			return nil, fmt.Errorf("error al listar repositorios: %w", err)
		}

		allRepos = append(allRepos, repos...)

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allRepos, nil
}

func (c *Client) GetContents(owner, repo, path string) ([]byte, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("cliente GitHub no inicializado")
	}

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

	if content == nil {
		return nil, fmt.Errorf("contenido recibido es nil para %s/%s/%s", owner, repo, path)
	}

	decodedContent, err := content.GetContent()
	if err != nil {
		return nil, fmt.Errorf("error al decodificar contenido: %w", err)
	}

	if decodedContent == "" {
		return nil, fmt.Errorf("contenido decodificado está vacío")
	}

	return []byte(decodedContent), nil
}

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

	if contents == nil {
		return nil, fmt.Errorf("directorio vacío o contenido nil para %s/%s/%s", owner, repo, path)
	}

	return contents, nil
}

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

// GetAuthenticatedUserLogin returns just the authenticated user's login name
func (c *Client) GetAuthenticatedUserLogin() (string, error) {
	if c == nil || c.client == nil {
		return "", fmt.Errorf("cliente GitHub no inicializado")
	}

	user, _, err := c.client.Users.Get(c.ctx, "")
	if err != nil {
		return "", fmt.Errorf("error al obtener usuario autenticado: %w", err)
	}

	return user.GetLogin(), nil
}

// ForkRepository creates a fork of the specified repository
func (c *Client) ForkRepository(owner, repo string) (*models.Repository, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("cliente GitHub no inicializado")
	}

	// Try to fork the repository
	fork, _, err := c.client.Repositories.CreateFork(c.ctx, owner, repo, &gh.RepositoryCreateForkOptions{})
	if err != nil {
		// Check if error is because fork already exists
		if _, ok := err.(*gh.AcceptedError); ok {
			// This is expected, GitHub returns 202 Accepted when fork is in progress
			// Let's try to get the existing fork
			user, err := c.GetAuthenticatedUserLogin()
			if err != nil {
				return nil, fmt.Errorf("error al obtener usuario para buscar fork existente: %w", err)
			}

			existingFork, _, err := c.client.Repositories.Get(c.ctx, user, repo)
			if err != nil {
				return nil, fmt.Errorf("error al obtener fork existente: %w", err)
			}

			fork = existingFork
		} else {
			return nil, fmt.Errorf("error al crear fork: %w", err)
		}
	}

	// Convert to our Repository model
	result := &models.Repository{
		FullName:      fork.GetFullName(),
		Name:          fork.GetName(),
		Owner:         fork.GetOwner().GetLogin(),
		CloneURL:      fork.GetCloneURL(),
		DefaultBranch: fork.GetDefaultBranch(),
		Language:      fork.GetLanguage(),
	}

	return result, nil
}

// CreatePullRequest creates a pull request in the specified repository
func (c *Client) CreatePullRequest(owner, repo, head, base, title, body string) (*gh.PullRequest, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("cliente GitHub no inicializado")
	}

	newPR := &gh.NewPullRequest{
		Title:               &title,
		Head:                &head,
		Base:                &base,
		Body:                &body,
		MaintainerCanModify: gh.Bool(true),
	}

	pr, _, err := c.client.PullRequests.Create(c.ctx, owner, repo, newPR)
	if err != nil {
		return nil, fmt.Errorf("error al crear pull request: %w", err)
	}

	return pr, nil
}

// DeleteRepository deletes the specified repository
func (c *Client) DeleteRepository(owner, repo string) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("cliente GitHub no inicializado")
	}

	_, err := c.client.Repositories.Delete(c.ctx, owner, repo)
	if err != nil {
		return fmt.Errorf("error al eliminar repositorio: %w", err)
	}

	return nil
}
