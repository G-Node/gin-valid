package web

import (
	"bytes"
	"github.com/G-Node/gin-valid/internal/config"
	"github.com/G-Node/gin-valid/internal/resources/templates"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var password = "student"
var weburl = "https://gin.dev.g-node.org:443"
var giturl = "git@gin.dev.g-node.org:22"

func TestUserCookieExp(t *testing.T) {
	res := cookieExp()
	if reflect.TypeOf(res).String() != "time.Time" {
		t.Fatalf(`cookieExp() = %q`, res)
	}
}

func TestUserDoLoginFailed(t *testing.T) {
	srvcfg := config.Read()
	srvcfg.GINAddresses.WebURL = weburl
	srvcfg.GINAddresses.GitURL = giturl
	config.Set(srvcfg)
	sessionid, err := doLogin("wtf", "wtf")
	if sessionid != "" || err == nil {
		t.Fatalf(`doLogin(username, password) = %q, %v`, sessionid, err)
	}
}

func TestUserDoLoginOK(t *testing.T) {
	tokens, _ := ioutil.TempDir("", "tokens")
	srvcfg := config.Read()
	srvcfg.GINAddresses.WebURL = weburl
	srvcfg.GINAddresses.GitURL = giturl
	srvcfg.Dir.Tokens = tokens
	config.Set(srvcfg)
	tokendir := filepath.Join(tokens, "by-sessionid")
	os.MkdirAll(tokendir, 0755)
	sessionid, err := doLogin(username, password)
	if sessionid == "" || err != nil {
		t.Fatalf(`doLogin(username, password) = %q, %v`, sessionid, err)
	}
}

func TestUserLoginPost(t *testing.T) {
	tokens, _ := ioutil.TempDir("", "tokens")
	srvcfg := config.Read()
	srvcfg.GINAddresses.WebURL = weburl
	srvcfg.GINAddresses.GitURL = giturl
	srvcfg.Dir.Tokens = tokens
	config.Set(srvcfg)
	tokendir := filepath.Join(tokens, "by-sessionid")
	os.MkdirAll(tokendir, 0755)
	v := make(url.Values)
	v.Set("username", username)
	v.Set("password", password)
	router := mux.NewRouter()
	router.HandleFunc("/login/{username}/{password}", LoginPost).Methods("POST")
	r, _ := http.NewRequest("POST", filepath.Join("/login", username, password), strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusFound {
		t.Fatalf(`LoginPost(w http.ResponseWriter, r *http.Request) status code = %v`, status)
	}
}

func TestUserLoginGet(t *testing.T) {
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/login", LoginGet).Methods("GET")
	r, _ := http.NewRequest("GET", "/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf(`LoginGet(w http.ResponseWriter, r *http.Request) status code = %v`, status)
	}
}

func TestUserLoginGetBadLoginPage(t *testing.T) {
	original := templates.Login
	templates.Login = "{{ WTF? }"
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/login", LoginGet).Methods("GET")
	r, _ := http.NewRequest("GET", "/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	templates.Login = original
	status := w.Code
	if status != http.StatusInternalServerError {
		t.Fatalf(`LoginGet(w http.ResponseWriter, r *http.Request) status code = %v`, status)
	}
}

func TestUserLoginGetBadLayout(t *testing.T) {
	original := templates.Layout
	templates.Layout = "{{ WTF? }"
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/login", LoginGet).Methods("GET")
	r, _ := http.NewRequest("GET", "/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	templates.Layout = original
	status := w.Code
	if status != http.StatusInternalServerError {
		t.Fatalf(`LoginGet(w http.ResponseWriter, r *http.Request) status code = %v`, status)
	}
}
