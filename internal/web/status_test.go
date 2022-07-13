package web

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/G-Node/gin-valid/internal/config"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestStatusOK(t *testing.T) {
	resultfldr, err := ioutil.TempDir("", "TestStatusOK")
	if err != nil {
		t.Fatalf("error creating temp dir: %s", err.Error())
	}
	defer os.RemoveAll(resultfldr)

	username := "valid-testing"
	reponame := "Testing"
	body := []byte("{}")

	router := mux.NewRouter()
	router.HandleFunc("/status/{validator}/{user}/{repo}", Status).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/status/bids", username, reponame), bytes.NewReader(body))
	w := httptest.NewRecorder()

	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))

	resdir := filepath.Join(resultfldr, "bids", username, reponame, srvcfg.Label.ResultsFolder)
	filename := filepath.Join(resdir, srvcfg.Label.ResultsBadge)
	content := "wtf"
	err = createTestResultDirs(resdir, filename, content)
	if err != nil {
		t.Fatal(err.Error())
	}

	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Status(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestStatusNoConent(t *testing.T) {
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/status/{validator}/{user}/{repo}", Status).Methods("GET")
	r, _ := http.NewRequest("GET", "/status/bids/whatever/whatever", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srvcfg := config.Read()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))

	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Status(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestStatusUnsupportedValidator(t *testing.T) {
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/status/{validator}/{user}/{repo}", Status).Methods("GET")
	r, _ := http.NewRequest("GET", "/status/whatever/whatever/whatever", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srvcfg := config.Read()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))

	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Status(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}
