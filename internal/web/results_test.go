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
	tmpdir, err := ioutil.TempDir("", "TestResultsUnsupportedV2")
	if err != nil {
		t.Fatalf("error creating temp dir: %s", err.Error())
	}
	defer os.RemoveAll(tmpdir)

	resultfldr := filepath.Join(tmpdir, "results")
	err = os.Mkdir(resultfldr, 0755)
	if err != nil {
		t.Fatalf("error creating results dir: %s", err.Error())
	}

	username := "valid-testing"
	reponame := "Testing"
	id := "1"
	body := []byte("{}")

	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/results/wtf", username, "/", reponame, "/", id), bytes.NewReader(body))
	w := httptest.NewRecorder()

	srvcfg := config.Read()
	srvcfg.Settings.Validators = append(srvcfg.Settings.Validators, "wtf")
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)

	resdir := filepath.Join(resultfldr, "nix", username, reponame, id)
	err = os.MkdirAll(resdir, 0755)
	if err != nil {
		t.Fatalf("error creating results directory: %s", err.Error())
	}
	f, err := os.Create(filepath.Join(resdir, srvcfg.Label.ResultsFile))
	if err != nil {
		t.Fatalf("error creating results file: %s", err.Error())
	}
	defer f.Close()
	_, err = f.WriteString(`{"empty":"json"}`)
	if err != nil {
		t.Fatalf("error writing to results file: %s", err.Error())
	}

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
	tmpdir, err := ioutil.TempDir("", "TestResultsODML")
	if err != nil {
		t.Fatalf("error creating temp dir: %s", err.Error())
	}
	defer os.RemoveAll(tmpdir)

	resultfldr := filepath.Join(tmpdir, "results")
	err = os.Mkdir(resultfldr, 0755)
	if err != nil {
		t.Fatalf("error creating results dir: %s", err.Error())
	}

	username := "valid-testing"
	reponame := "Testing"
	id := "1"
	body := []byte("{}")

	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/results/odml", username, reponame, id), bytes.NewReader(body))
	w := httptest.NewRecorder()

	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)

	resdir := filepath.Join(resultfldr, "odml", username, reponame, id)
	err = os.MkdirAll(resdir, 0755)
	if err != nil {
		t.Fatalf("error creating results folder: %s", err.Error())
	}
	f, err := os.Create(filepath.Join(resdir, srvcfg.Label.ResultsFile))
	if err != nil {
		t.Fatalf("error creating results file: %s", err.Error())
	}
	defer f.Close()
	_, err = f.WriteString(`{"empty":"json"}`)
	if err != nil {
		t.Fatalf("error writing to results file: %s", err.Error())
	}

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
	tmpdir, err := ioutil.TempDir("", "TestResultsNIX")
	if err != nil {
		t.Fatalf("error creating temp dir: %s", err.Error())
	}
	defer os.RemoveAll(tmpdir)

	resultfldr := filepath.Join(tmpdir, "results")
	err = os.Mkdir(resultfldr, 0755)
	if err != nil {
		t.Fatalf("error creating results dir: %s", err.Error())
	}

	username := "valid-testing"
	reponame := "Testing"
	id := "1"
	body := []byte("{}")

	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/results/nix", username, "/", reponame, "/", id), bytes.NewReader(body))
	w := httptest.NewRecorder()

	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)

	resdir := filepath.Join(resultfldr, "nix", username, reponame, id)
	err = os.MkdirAll(resdir, 0755)
	if err != nil {
		t.Fatalf("error creating results folder: %s", err.Error())
	}
	f, err := os.Create(filepath.Join(resdir, srvcfg.Label.ResultsFile))
	if err != nil {
		t.Fatalf("error creating results file: %s", err.Error())
	}
	defer f.Close()
	_, err = f.WriteString(`{"empty":"json"}`)
	if err != nil {
		t.Fatalf("error writing to results file: %s", err.Error())
	}

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
	tmpdir, err := ioutil.TempDir("", "TestResultsInJSON")
	if err != nil {
		t.Fatalf("error creating temp dir: %s", err.Error())
	}
	defer os.RemoveAll(tmpdir)

	resultfldr := filepath.Join(tmpdir, "results")
	err = os.Mkdir(resultfldr, 0755)
	if err != nil {
		t.Fatalf("error creating results dir: %s", err.Error())
	}

	username := "valid-testing"
	reponame := "Testing"
	id := "1"
	body := []byte("{}")

	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/results/bids", username, "/", reponame, "/", id), bytes.NewReader(body))
	w := httptest.NewRecorder()

	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)

	resdir := filepath.Join(resultfldr, "bids", username, reponame, id)
	err = os.MkdirAll(resdir, 0755)
	if err != nil {
		t.Fatalf("error creating results folder: %s", err.Error())
	}
	f, err := os.Create(filepath.Join(resdir, srvcfg.Label.ResultsFile))
	if err != nil {
		t.Fatalf("error creating results file: %s", err.Error())
	}
	defer f.Close()
	_, err = f.WriteString(`{"empty":"json"}`)
	if err != nil {
		t.Fatalf("error writing to results file: %s", err.Error())
	}

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
	tmpdir, err := ioutil.TempDir("", "TestResultsInProgress")
	if err != nil {
		t.Fatalf("error creating temp dir: %s", err.Error())
	}
	defer os.RemoveAll(tmpdir)

	resultfldr := filepath.Join(tmpdir, "results")
	err = os.Mkdir(resultfldr, 0755)
	if err != nil {
		t.Fatalf("error creating results dir: %s", err.Error())
	}

	username := "valid-testing"
	reponame := "Testing"
	id := "1"

	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/results/bids", username, "/", reponame, "/", id), bytes.NewReader(body))
	w := httptest.NewRecorder()

	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)

	resdir := filepath.Join(resultfldr, "bids", username, reponame, id)
	err = os.MkdirAll(resdir, 0755)
	if err != nil {
		t.Fatalf("error creating results folder: %s", err.Error())
	}
	f, err := os.Create(filepath.Join(resdir, srvcfg.Label.ResultsFile))
	if err != nil {
		t.Fatalf("error creating results file: %s", err.Error())
	}
	defer f.Close()
	_, err = f.WriteString(progressmsg)
	if err != nil {
		t.Fatalf("error writing to results file: %s", err.Error())
	}

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
	tmpdir, err := ioutil.TempDir("", "TestResultsSomeResults")
	if err != nil {
		t.Fatalf("error creating temp dir: %s", err.Error())
	}
	defer os.RemoveAll(tmpdir)

	resultfldr := filepath.Join(tmpdir, "results")
	err = os.Mkdir(resultfldr, 0755)
	if err != nil {
		t.Fatalf("error creating results dir: %s", err.Error())
	}

	username := "valid-testing"
	reponame := "Testing"
	id := "1"
	body := []byte("{}")

	router := mux.NewRouter()
	router.HandleFunc("/results/{validator}/{user}/{repo}/{id}", Results).Methods("GET")
	r, _ := http.NewRequest("GET", filepath.Join("/results/bids", username, "/", reponame, "/", id), bytes.NewReader(body))
	w := httptest.NewRecorder()

	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)

	resdir := filepath.Join(resultfldr, "bids", username, reponame, id)
	err = os.MkdirAll(resdir, 0755)
	if err != nil {
		t.Fatalf("error creating results folder: %s", err.Error())
	}
	f, err := os.Create(filepath.Join(resdir, srvcfg.Label.ResultsFile))
	if err != nil {
		t.Fatalf("error creating results file: %s", err.Error())
	}
	defer f.Close()
	_, err = f.WriteString("wtf")
	if err != nil {
		t.Fatalf("error writing to results file: %s", err.Error())
	}

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
