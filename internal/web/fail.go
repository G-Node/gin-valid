package web

import (
	"html/template"
	"net/http"
	"time"

	"github.com/G-Node/gin-valid/internal/config"
	"github.com/G-Node/gin-valid/internal/log"
	"github.com/G-Node/gin-valid/internal/resources/templates"
)

// fail logs an error and renders an error page with the given message,
// returning the given status code to the user.
func fail(w http.ResponseWriter, r *http.Request, status int, message string) {
	log.ShowWrite("[Info] displaying error message %s", message)
	w.WriteHeader(status)

	tmpl := template.New("layout")
	tmpl, err := tmpl.Parse(templates.Layout)
	if err != nil {
		log.ShowWrite("[Error] failed to parse html layout page. Displaying error message without layout: %s", err.Error())
		tmpl = template.New("content")
	}
	tmpl, err = tmpl.Parse(templates.Fail)
	if err != nil {
		log.ShowWrite("[Error] failed to render fail page. Displaying plain error message: %s", err.Error())
		_, err = w.Write([]byte(message))
		if err != nil {
			log.ShowWrite("[Error] failed to write plain error message: %s", err.Error())
		}
		return
	}
	year, _, _ := time.Now().Date()
	loggedUsername := ""
	if r != nil {
		loggedUsername = getLoggedUserName(r)
	}
	srvcfg := config.Read()
	errinfo := struct {
		StatusCode  int
		StatusText  string
		Message     string
		GinURL      string
		CurrentYear int
		UserName    string
	}{
		status,
		http.StatusText(status),
		message,
		srvcfg.GINAddresses.WebURL,
		year,
		loggedUsername,
	}
	err = tmpl.Execute(w, &errinfo)
	if err != nil {
		log.ShowWrite("[Error] failed to parse error info to page: %s", err.Error())
	}
}
