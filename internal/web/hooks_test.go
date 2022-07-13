package web

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/G-Node/gin-valid/internal/config"
	"github.com/gorilla/mux"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestHooksDisable(t *testing.T) {
	username := "valid-testing"
	reponame := "Testing"

	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/repos/{user}/{repo}/{hookid}/disable", DisableHook).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/repos/", username, "/", reponame, "/1/disable"), bytes.NewReader(body))
	w := httptest.NewRecorder()
	srvcfg := config.Read()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusFound {
		t.Fatalf("DisableHook(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestHooksEnable(t *testing.T) {
	username := "valid-testing"
	reponame := "Testing"

	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/repos/{user}/{repo}/{validator}/enable", EnableHook).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/repos/", username, "/", reponame, "/bids/enable"), bytes.NewReader(body))
	w := httptest.NewRecorder()
	srvcfg := config.Read()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusFound {
		t.Fatalf("EnableHook(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}
