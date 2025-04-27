module github.com/cmalvaceda/tesis-poc

go 1.23.0

toolchain go1.24.2

require (
	github.com/google/go-github/v60 v60.0.0
	github.com/joho/godotenv v1.5.1
	golang.org/x/oauth2 v0.29.0
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/google/go-querystring v1.1.0 // indirect

// Añade la directiva replace para forzar una versión diferente de go-crypto
replace github.com/ProtonMail/go-crypto v0.0.0-20230825050710-9ee0b59f6bdb => github.com/ProtonMail/go-crypto v0.0.0-20230217180103-958b8693f3d6

// go mod tidy regenerará las dependencias indirectas aquí abajo
