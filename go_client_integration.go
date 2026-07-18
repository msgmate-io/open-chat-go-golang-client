package goclientintegration

import (
	_ "embed"
	"strings"

	"github.com/msgmate-io/go-integration-interface/integrationinterface"
)

//go:embed README.md
var readmeMarkdown string

func init() {
	integrationinterface.MustRegister(integrationinterface.Definition{
		Name:           "go_client_integration",
		AdminOnly:      false,
		UserAccessible: false,
		ReadmeMarkdown: strings.TrimSpace(readmeMarkdown),
	})
}
