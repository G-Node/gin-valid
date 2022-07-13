package web

import (
	"github.com/G-Node/gin-valid/internal/resources/templates"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFailFailedToParse(t *testing.T) {
	w := httptest.NewRecorder()
	original := templates.Layout
	templates.Layout = "{{ WTF? }"
	fail(w, nil, 200, "WTF")
	templates.Layout = original
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("fail(w http.ResponseWriter, status int, message string) status code = %d", status)
	}
}

func TestFailFailedToParseFailPage(t *testing.T) {
	w := httptest.NewRecorder()
	original := templates.Fail
	templates.Fail = "{{ WTF? }"
	fail(w, nil, 200, "WTF")
	templates.Fail = original
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("fail(w http.ResponseWriter, status int, message string) status code = %d", status)
	}
}
