module github.com/msgmate-io/go-client-integration

go 1.25.10

require (
	github.com/msgmate-io/go-integration-interface v0.0.0
	github.com/oapi-codegen/runtime v1.6.0
	github.com/urfave/cli/v3 v3.10.1
	golang.org/x/crypto v0.46.0
	golang.org/x/term v0.38.0
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	gorm.io/gorm v1.25.12 // indirect
)

replace github.com/msgmate-io/go-integration-interface => ../../go_integration_interface
