package web

import (
	"bytes"
	gweb "github.com/G-Node/gin-cli/web"
	"github.com/G-Node/gin-valid/internal/config"
	"github.com/G-Node/gin-valid/internal/resources/templates"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

var weburl = "https://gin.dev.g-node.org:443"
var giturl = "git@gin.dev.g-node.org:22"

func TestUserCookieExp(t *testing.T) {
	res := cookieExp()
	if reflect.TypeOf(res).String() != "time.Time" {
		t.Fatalf("cookieExp() = %q", res)
	}
}

func TestUserDoLoginFailed(t *testing.T) {
	srvcfg := config.Read()
	srvcfg.GINAddresses.WebURL = weburl
	srvcfg.GINAddresses.GitURL = giturl
	config.Set(srvcfg)
	sessionid, err := doLogin("wtf", "wtf")
	if sessionid != "" || err == nil {
		t.Fatalf("doLogin(username, password) = %q, %s", sessionid, err.Error())
	}
}

func TestGetLoggedUserNameEmpty(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	q := getLoggedUserName(r)
	if q != "" {
		t.Fatalf("getLoggedUserName(r *http.Request) = %q", q)
	}
}

func TestGetLoggedUserNameSessionDoesNotExists(t *testing.T) {
	srvcfg := config.Read()
	w := httptest.NewRecorder()
	cookie := &http.Cookie{
		Name:    srvcfg.Settings.CookieName,
		Value:   "wtfsession",
		Expires: cookieExp(),
	}
	http.SetCookie(w, cookie)
	r := &http.Request{Header: http.Header{"Cookie": []string{cookie.String()}}}
	q := getLoggedUserName(r)
	if q != "" {
		t.Fatalf("getLoggedUserName(r *http.Request) = %q", q)
	}
}

func TestGetLoggedUserNameOK(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "TestGetLoggedUserNameOK")
	if err != nil {
		t.Fatalf("error creating temp dir: %s", err.Error())
	}
	defer os.RemoveAll(tmpdir)

	tokenfldr := filepath.Join(tmpdir, "tokens")
	err = os.MkdirAll(filepath.Join(tokenfldr, "by-sessionid"), 0755)
	if err != nil {
		t.Fatalf("error creating token dir: %s", err.Error())
	}

	srvcfg := config.Read()
	srvcfg.Dir.Tokens = tokenfldr
	config.Set(srvcfg)

	w := httptest.NewRecorder()
	cookie := &http.Cookie{
		Name:    srvcfg.Settings.CookieName,
		Value:   "wtfsession",
		Expires: cookieExp(),
	}
	http.SetCookie(w, cookie)
	r := &http.Request{Header: http.Header{"Cookie": []string{cookie.String()}}}
	ut := gweb.UserToken{
		Username: "wtf_user",
		Token:    "wtf_token",
	}
	err = saveToken(ut)
	if err != nil {
		t.Fatalf("getLoggedUserName(r *http.Request) = %s", err.Error())
	}
	err = linkToSession("wtf_user", "wtfsession")
	if err != nil {
		t.Fatalf("getLoggedUserName(r *http.Request) = %s", err.Error())
	}
	q := getLoggedUserName(r)
	if q != "wtf_user" {
		t.Fatalf("getLoggedUserName(r *http.Request) = %q", q)
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
		t.Fatalf("LoginGet(w http.ResponseWriter, r *http.Request) status code = %d", status)
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
		t.Fatalf("LoginGet(w http.ResponseWriter, r *http.Request) status code = %d", status)
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
		t.Fatalf("LoginGet(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

/*
// Refactor tests to remove the dev server dependency
var password = "student"

func TestUserDoLoginOK(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "TestGetLoggedUserNameOK")
	if err != nil {
		t.Fatalf("error creating temp dir: %s", err.Error())
	}
	defer os.RemoveAll(tmpdir)

	tokenfldr := filepath.Join(tmpdir, "tokens")
	err = os.MkdirAll(filepath.Join(tokenfldr, "by-sessionid"), 0755)
	if err != nil {
		t.Fatalf("error creating token dir: %s", err.Error())
	}

	srvcfg := config.Read()
	srvcfg.Dir.Tokens = tokenfldr
	srvcfg.GINAddresses.WebURL = weburl
	srvcfg.GINAddresses.GitURL = giturl
	config.Set(srvcfg)

	sessionid, err := doLogin(username, password)
	if sessionid == "" || err != nil {
		t.Fatalf("doLogin(username, password) = %q, %s", sessionid, err.Error())
	}
}

func TestUserLoginPost(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "TestGetLoggedUserNameOK")
	if err != nil {
		t.Fatalf("error creating temp dir: %s", err.Error())
	}
	defer os.RemoveAll(tmpdir)

	tokenfldr := filepath.Join(tmpdir, "tokens")
	err = os.MkdirAll(filepath.Join(tokenfldr, "by-sessionid"), 0755)
	if err != nil {
		t.Fatalf("error creating token dir: %s", err.Error())
	}

	srvcfg := config.Read()
	srvcfg.Dir.Tokens = tokenfldr
	srvcfg.GINAddresses.WebURL = weburl
	srvcfg.GINAddresses.GitURL = giturl
	config.Set(srvcfg)

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
		t.Fatalf("LoginPost(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}*/
