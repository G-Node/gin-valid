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

func TestResultsUnsupportedV2(t *testing.T) {
	username := "valid-testing"
	reponame := "Testing"

	id := "1"
	content := `{"empty":"json"}`
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/results/wtf", username, "/", reponame, "/", id), bytes.NewReader(body))
	w := httptest.NewRecorder()
	resultfldr, _ := ioutil.TempDir("", "results")
	srvcfg := config.Read()
	srvcfg.Settings.Validators = append(srvcfg.Settings.Validators, "wtf")
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)
	os.MkdirAll(filepath.Join(resultfldr, "nix", username, reponame, id), 0755)
	f, _ := os.Create(filepath.Join(resultfldr, "nix", username, reponame, id, srvcfg.Label.ResultsFile))
	defer f.Close()
	f.WriteString(content)
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	srvcfg.Settings.Validators = srvcfg.Settings.Validators[:len(srvcfg.Settings.Validators)-1]
	config.Set(srvcfg)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Results(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestResultsODML(t *testing.T) {
	username := "valid-testing"
	reponame := "Testing"

	id := "1"
	content := `{"empty":"json"}`
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/results/odml", username, reponame, id), bytes.NewReader(body))
	w := httptest.NewRecorder()
	parent := os.TempDir()
	pth := filepath.Join(parent, "results")
	os.Mkdir(pth, 0755)
	resultfldr, _ := ioutil.TempDir(pth, "*-res")
	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)
	os.MkdirAll(filepath.Join(resultfldr, "odml", username, reponame, id), 0755)
	f, _ := os.Create(filepath.Join(resultfldr, "odml", username, reponame, id, srvcfg.Label.ResultsFile))
	defer f.Close()
	f.WriteString(content)
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Results(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestResultsNIX(t *testing.T) {
	username := "valid-testing"
	reponame := "Testing"

	id := "1"
	content := `{"empty":"json"}`
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/results/nix", username, "/", reponame, "/", id), bytes.NewReader(body))
	w := httptest.NewRecorder()
	parent := os.TempDir()
	pth := filepath.Join(parent, "results")
	os.Mkdir(pth, 0755)
	resultfldr, _ := ioutil.TempDir(pth, "*-res")
	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)
	os.MkdirAll(filepath.Join(resultfldr, "nix", username, reponame, id), 0755)
	f, _ := os.Create(filepath.Join(resultfldr, "nix", username, reponame, id, srvcfg.Label.ResultsFile))
	defer f.Close()
	f.WriteString(content)
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Results(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestResultsInJSON(t *testing.T) {
	username := "valid-testing"
	reponame := "Testing"

	id := "1"
	content := `{"empty":"json"}`
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/results/bids", username, "/", reponame, "/", id), bytes.NewReader(body))
	w := httptest.NewRecorder()
	parent := os.TempDir()
	pth := filepath.Join(parent, "results")
	os.Mkdir(pth, 0755)
	resultfldr, _ := ioutil.TempDir(pth, "*-res")
	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)
	os.MkdirAll(filepath.Join(resultfldr, "bids", username, reponame, id), 0755)
	f, _ := os.Create(filepath.Join(resultfldr, "bids", username, reponame, id, srvcfg.Label.ResultsFile))
	defer f.Close()
	f.WriteString(content)
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Results(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestResultsInProgress(t *testing.T) {
	username := "valid-testing"
	reponame := "Testing"

	id := "1"
	content := progressmsg
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/results/bids", username, "/", reponame, "/", id), bytes.NewReader(body))
	w := httptest.NewRecorder()
	parent := os.TempDir()
	pth := filepath.Join(parent, "results")
	os.Mkdir(pth, 0755)
	resultfldr, _ := ioutil.TempDir(pth, "*-res")
	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)
	os.MkdirAll(filepath.Join(resultfldr, "bids", username, reponame, id), 0755)
	f, _ := os.Create(filepath.Join(resultfldr, "bids", username, reponame, id, srvcfg.Label.ResultsFile))
	defer f.Close()
	f.WriteString(content)
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Results(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestResultsSomeResults(t *testing.T) {
	username := "valid-testing"
	reponame := "Testing"

	id := "1"
	content := "wtf"
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/results/bids", username, "/", reponame, "/", id), bytes.NewReader(body))
	w := httptest.NewRecorder()
	parent := os.TempDir()
	pth := filepath.Join(parent, "results")
	os.Mkdir(pth, 0755)
	resultfldr, _ := ioutil.TempDir(pth, "*-res")
	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)
	os.MkdirAll(filepath.Join(resultfldr, "bids", username, reponame, id), 0755)
	f, _ := os.Create(filepath.Join(resultfldr, "bids", username, reponame, id, srvcfg.Label.ResultsFile))
	defer f.Close()
	f.WriteString(content)
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Results(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestResultsNoResults(t *testing.T) {
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", "/results/bids/whatever/whatever/whatever", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srvcfg := config.Read()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Results(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestResultsUnsupportedValidator(t *testing.T) {
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", "/results/wtf/whatever/whatever/whatever", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srvcfg := config.Read()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Results(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestResultsIDNotSpecified(t *testing.T) {
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/", Results).Methods("GET")
	r, _ := http.NewRequest("GET", "/results/bids/whatever/whatever/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srvcfg := config.Read()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Results(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}
