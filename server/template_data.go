package server

import (
	"embed"
	"net/http"
	"text/template"

	kratos "github.com/ory/kratos-client-go"
)

type Metadata struct {
	Registration bool `json:"registration"`
	Verification bool `json:"verification"`
}

// templateData contains data for template
type templateData struct {
	Title     string
	UI        *kratos.UiContainer
	Details   string
	Metadata  Metadata
	Templates embed.FS
}

// Render renders template with provided data
func (td *templateData) Render(w http.ResponseWriter) {
	// render template index.html
	tmpl := template.Must(template.ParseFS(td.Templates, "templates/index.html"))
	if err := tmpl.Execute(w, td); err != nil {
		writeError(w, http.StatusInternalServerError, err)
	}
}
