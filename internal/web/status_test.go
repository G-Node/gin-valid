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
	err = os.MkdirAll(resdir, 0755)
	if err != nil {
		t.Fatalf("error creating results folder: %s", err.Error())
	}
	f, err := os.Create(filepath.Join(resdir, srvcfg.Label.ResultsBadge))
	if err != nil {
		t.Fatalf("error creating results file: %s", err.Error())
	}
	defer f.Close()
	_, err = f.WriteString("wtf")
	if err != nil {
		t.Fatalf("error writing to results file: %s", err.Error())
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
