package handle

import (
	"html/template"
	"net/http"
)

func HandleCASLogin(tmpl *template.Template, sessProvider SessionProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

	}
}

func HandleCASServiceValidate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

	}
}
