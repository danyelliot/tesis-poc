# Code Citations

## License: unknown
https://github.com/daviaraujocc/Githubrunner-operator/blob/ea46e485446c03af2434a139fe0d05a3a3b8dd36/github/github.go

```
string) (*Client, error
```


## License: unknown
https://github.com/daviaraujocc/Githubrunner-operator/blob/ea46e485446c03af2434a139fe0d05a3a3b8dd36/github/github.go

```
string) (*Client, error) {
	ctx := context.Background()
```


## License: unknown
https://github.com/daviaraujocc/Githubrunner-operator/blob/ea46e485446c03af2434a139fe0d05a3a3b8dd36/github/github.go

```
string) (*Client, error) {
	ctx := context.Background()
	ts := oauth2.StaticToken
```


## License: unknown
https://github.com/daviaraujocc/Githubrunner-operator/blob/ea46e485446c03af2434a139fe0d05a3a3b8dd36/github/github.go

```
string) (*Client, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{
```


## License: unknown
https://github.com/daviaraujocc/Githubrunner-operator/blob/ea46e485446c03af2434a139fe0d05a3a3b8dd36/github/github.go

```
string) (*Client, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	
```


## License: unknown
https://github.com/daviaraujocc/Githubrunner-operator/blob/ea46e485446c03af2434a139fe0d05a3a3b8dd36/github/github.go

```
string) (*Client, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx,
```


## License: unknown
https://github.com/daviaraujocc/Githubrunner-operator/blob/ea46e485446c03af2434a139fe0d05a3a3b8dd36/github/github.go

```
string) (*Client, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient
```


## License: unknown
https://github.com/daviaraujocc/Githubrunner-operator/blob/ea46e485446c03af2434a139fe0d05a3a3b8dd36/github/github.go

```
string) (*Client, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)
```

