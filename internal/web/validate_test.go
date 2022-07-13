package web

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	gweb "github.com/G-Node/gin-cli/web"
	"github.com/G-Node/gin-valid/internal/config"
	"github.com/G-Node/gin-valid/internal/resources/templates"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValiateBadConfig(t *testing.T) {
	valcfg, err := handleValidationConfig("wtf")
	if err == nil {
		t.Fatalf("handleValidationConfig(cfgpath string) = %v", valcfg)
	}
}

func TestValidateNotYAML(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "TestValidateNotYAML")
	if err != nil {
		t.Fatalf("error creating temp dir: %s", err.Error())
	}
	testfile := filepath.Join(tmpdir, "testing-config.json")
	f, err := os.Create(testfile)
	if err != nil {
		t.Fatalf("error creating json file: %s", err.Error())
	}
	defer f.Close()

	_, err = f.WriteString("foo: somebody said I should put a colon here: so I did")
	if err != nil {
		t.Fatalf("error writing to testfile: %s", err.Error())
	}
	valcfg, err := handleValidationConfig(testfile)
	if err == nil {
		t.Fatalf("expected error validating config, but got none; cfg: %v", valcfg)
	}
	defer os.RemoveAll(tmpdir)
}

func TestValidateGoodConfig(t *testing.T) {
	f, _ := os.Create("testing-config.json")
	f.WriteString(`empty: "true"`)
	f.Close()
	valcfg, err := handleValidationConfig("testing-config.json")
	os.RemoveAll("testing-config.json")
	if err != nil {
		t.Fatalf("handleValidationConfig(cfgpath string) = %v, %s", valcfg, err.Error())
	}
}

func TestValidateBIDSNoData(t *testing.T) {
	err := validateBIDS("wtf", "wtf")
	if err == nil {
		t.Fatal("validateBIDS; expected error but got none")
	}
}

func TestValidateNIXNoData(t *testing.T) {
	err := validateNIX("wtf", "wtf")
	if err == nil {
		t.Fatal("validateNIX; expected error but got none")
	}
}

func TestValidateODMLNoData(t *testing.T) {
	err := validateODML("wtf", "wtf")
	if err == nil {
		t.Fatal("validateODML; expected error but got none")
	}
}

func TestValidateBIDSOK(t *testing.T) {
	resultfldr, _ := ioutil.TempDir("", "results")
	tempdataset, _ := ioutil.TempDir("", "tempdataset")
	f, err := os.Create(filepath.Join(tempdataset, "ginvalidation.yaml"))
	if err != nil {
		t.Fatalf("Could not create yaml file: %s", err.Error())
	}
	defer f.Close()
	_, err = f.WriteString("bidsconfig:\n  bidsroot: 'bids_example'")
	if err != nil {
		t.Fatalf("validateBIDS(valroot, resdir string) = %s", err.Error())
	}
	os.Mkdir(filepath.Join(tempdataset, "bids_example"), 0664)
	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)
	validateBIDS(tempdataset, resultfldr)
}

func TestValidateNIXOK(t *testing.T) {
	resultfldr, _ := ioutil.TempDir("", "results")
	tempdataset, _ := ioutil.TempDir("", "tempdataset")
	nix, err := ioutil.ReadFile("../../resources/nixdata.nix")
	if err != nil {
		t.Fatalf("validateNIX(valroot, resdir string) = %s", err.Error())
	}
	err = ioutil.WriteFile(filepath.Join(tempdataset, "nixdata.nix"), nix, 0664)
	if err != nil {
		t.Fatalf("validateNIX(valroot, resdir string) = %s", err.Error())
	}
	os.Mkdir(filepath.Join(tempdataset, ".git"), 0755)
	nix = append([]byte("WTF_this_will_not_work"), nix...)
	err = ioutil.WriteFile(filepath.Join(tempdataset, ".git", "nixdata_donottest.nix"), nix, 0664)
	if err != nil {
		t.Fatalf("validateNIX(valroot, resdir string) = %s", err.Error())
	}
	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)
	validateNIX(tempdataset, resultfldr)
}

func TestValidateODMLOK(t *testing.T) {
	resultfldr, _ := ioutil.TempDir("", "results")
	tempdataset, _ := ioutil.TempDir("", "tempdataset")
	odml, err := ioutil.ReadFile("../../resources/odmldata.odml")
	if err != nil {
		t.Fatalf("validateODML(valroot, resdir string) = %s", err.Error())
	}
	err = ioutil.WriteFile(filepath.Join(tempdataset, "odmldata.odml"), odml, 0664)
	if err != nil {
		t.Fatalf("validateODML(valroot, resdir string) = %s", err.Error())
	}
	os.Mkdir(filepath.Join(tempdataset, ".git"), 0755)
	odml = append([]byte("WTF_this_will_not_work"), odml...)
	err = ioutil.WriteFile(filepath.Join(tempdataset, ".git", "odmldata_donottest.odml"), odml, 0664)
	if err != nil {
		t.Fatalf("validateODML(valroot, resdir string) = %s", err.Error())
	}
	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	config.Set(srvcfg)
	validateODML(tempdataset, resultfldr)
}

func TestValidatePubBrokenPubValidate(t *testing.T) {
	original := templates.PubValidate
	templates.PubValidate = "{{ WTF? }"
	srvcfg := config.Read()
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/pubvalidate", PubValidateGet).Methods("GET")
	r, _ := http.NewRequest("GET", "/pubvalidate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	templates.PubValidate = original
	status := w.Code
	if status != http.StatusInternalServerError {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestValidatePubBrokenLayout(t *testing.T) {
	original := templates.Layout
	templates.Layout = "{{ WTF? }"
	srvcfg := config.Read()
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/pubvalidate", PubValidateGet).Methods("GET")
	r, _ := http.NewRequest("GET", "/pubvalidate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	templates.Layout = original
	status := w.Code
	if status != http.StatusInternalServerError {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestValidatePub(t *testing.T) {
	srvcfg := config.Read()
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/pubvalidate", PubValidateGet).Methods("GET")
	r, _ := http.NewRequest("GET", "/pubvalidate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestValidateRepoDoesNotExists(t *testing.T) {
	username := "valid-testing"
	reponame := "Testing"

	token2 := "wtf"
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/validate/{validator}/{user}/{repo}", Validate).Methods("POST")
	resultfldr, _ := ioutil.TempDir("", "results")
	tempfldr, _ := ioutil.TempDir("", "temp")
	tokenfldr, _ := ioutil.TempDir("", "token")
	srvcfg := config.Read()
	srvcfg.Dir.Result = resultfldr
	srvcfg.Dir.Temp = tempfldr
	srvcfg.Dir.Tokens = tokenfldr
	config.Set(srvcfg)
	var tok gweb.UserToken
	tok.Username = username
	tok.Token = token2
	saveToken(tok)
	os.Mkdir(filepath.Join(tokenfldr, "by-repo"), 0755)
	linkToRepo(username, filepath.Join(username, "/", reponame))
	r, _ := http.NewRequest("POST", filepath.Join("/validate/bids/", username, "/", reponame), bytes.NewReader(body))
	w := httptest.NewRecorder()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	time.Sleep(5 * time.Second) // TODO HACK
	os.RemoveAll(filepath.Join(srvcfg.Dir.Tokens, "by-repo"))
	status := w.Code
	if status != http.StatusNotFound {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestValidateBadToken(t *testing.T) {
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/validate/{validator}/{user}/{repo}", Validate).Methods("POST")
	r, _ := http.NewRequest("POST", "/validate/bids/whatever/whatever", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srvcfg := config.Read()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	status := w.Code
	if status != http.StatusUnauthorized {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestValidateUnsupportedValidator(t *testing.T) {
	body := []byte("{}")
	r, _ := http.NewRequest("GET", "wtf", bytes.NewReader(body))
	srvcfg := config.Read()
	srvcfg.Settings.HookSecret = "hooksecret"
	config.Set(srvcfg)
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	w := httptest.NewRecorder()
	Validate(w, r)
	status := w.Code
	if status != http.StatusNotFound {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestValidateHookSecretFailed(t *testing.T) {
	r, _ := http.NewRequest("GET", "wtf", strings.NewReader("{}"))
	srvcfg := config.Read()
	srvcfg.Settings.HookSecret = "hooksecret"
	config.Set(srvcfg)
	r.Header.Add("X-Gogs-Signature", "wtf")
	w := httptest.NewRecorder()
	Validate(w, r)
	status := w.Code
	if status != http.StatusBadRequest {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestValidateBodyNotJSON(t *testing.T) {
	r, _ := http.NewRequest("GET", "wtf", strings.NewReader("wtf"))
	w := httptest.NewRecorder()
	Validate(w, r)
	status := w.Code
	if status != http.StatusBadRequest {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

type errReader int

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("test error")
}

func TestValidateBadBody(t *testing.T) {
	testRequest := httptest.NewRequest(http.MethodPost, "/something", errReader(0))
	w := httptest.NewRecorder()
	Validate(w, testRequest)
	status := w.Code
	if status != http.StatusBadRequest {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

/*
// Refactor tests to remove the dev server dependency
var token = "4c82d07cccf103e071ad9ee8aec82c34d7003c6c"

func TestValidateBIDSOK(t *testing.T) {
	testValidateOK(t, "bids")
}

func TestValidateNIXOK(t *testing.T) {
	testValidateOK(t, "nix")
}

func TestValidateODMLOK(t *testing.T) {
	testValidateOK(t, "odml")
}

func testValidateOK(t *testing.T, validator string) {
	body := []byte('{"after": "8cea328d5ee9d6d8944bd06802f761f140a31653"}')
	router := mux.NewRouter()
	router.HandleFunc("/validate/{validator}/{user}/{repo}", Validate).Methods("POST")
	srvcfg := config.Read()
	srvcfg.Dir.Tokens = "."
	os.Mkdir("tmp", 0755)
	srvcfg.Dir.Temp = "./tmp"
	srvcfg.GINAddresses.WebURL = weburl
	srvcfg.GINAddresses.GitURL = giturl
	config.Set(srvcfg)
	var tok gweb.UserToken
	tok.Username = username
	tok.Token = token
	saveToken(tok)
	os.Mkdir(filepath.Join(srvcfg.Dir.Tokens, "by-repo"), 0755)
	linkToRepo(username, filepath.Join(username, "/", reponame))
	r, err := http.NewRequest("POST", filepath.Join("/validate", validator, username, reponame), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) = %s", err.Error())
	}
	w := httptest.NewRecorder()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	time.Sleep(5 * time.Second) // TODO HACK
	os.RemoveAll(filepath.Join(srvcfg.Dir.Tokens, "by-repo"))
	os.RemoveAll("tmp")
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestValidateBadgeFail(t *testing.T) {
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/validate/{validator}/{user}/{repo}", Validate).Methods("POST")
	srvcfg := config.Read()
	resultfldr, _ := ioutil.TempDir("", "results")
	tempfldr, _ := ioutil.TempDir("", "temp")
	tokenfldr, _ := ioutil.TempDir("", "token")
	srvcfg.GINAddresses.WebURL = weburl
	srvcfg.GINAddresses.GitURL = giturl
	srvcfg.Dir.Result = resultfldr
	srvcfg.Dir.Temp = tempfldr
	srvcfg.Dir.Tokens = tokenfldr
	config.Set(srvcfg)
	var tok gweb.UserToken
	tok.Username = username
	tok.Token = token
	saveToken(tok)
	os.Mkdir(filepath.Join(tokenfldr, "by-repo"), 0755)
	linkToRepo(username, filepath.Join(username, "/", reponame))
	r, err := http.NewRequest("POST", filepath.Join("/validate/bids/", username, "/", reponame), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) = %s", err.Error())
	}
	w := httptest.NewRecorder()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	time.Sleep(5 * time.Second) // TODO HACK
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}

func TestValidateTMPFail(t *testing.T) {
	body := []byte("{}")
	router := mux.NewRouter()
	router.HandleFunc("/validate/{validator}/{user}/{repo}", Validate).Methods("POST")
	srvcfg := config.Read()
	resultfldr, _ := ioutil.TempDir("", "results")
	tempfldr, _ := ioutil.TempDir("", "temp")
	tokenfldr, _ := ioutil.TempDir("", "token")
	srvcfg.GINAddresses.WebURL = weburl
	srvcfg.GINAddresses.GitURL = giturl
	srvcfg.Dir.Result = resultfldr
	srvcfg.Dir.Temp = tempfldr
	srvcfg.Dir.Tokens = tokenfldr
	config.Set(srvcfg)
	var tok gweb.UserToken
	tok.Username = username
	tok.Token = token
	saveToken(tok)
	os.Mkdir(filepath.Join(tokenfldr, "by-repo"), 0755)
	linkToRepo(username, filepath.Join(username, "/", reponame))
	r, _ := http.NewRequest("POST", filepath.Join("/validate/bids/", username, "/", reponame), bytes.NewReader(body))
	w := httptest.NewRecorder()
	sig := hmac.New(sha256.New, []byte(srvcfg.Settings.HookSecret))
	sig.Write(body)
	r.Header.Add("X-Gogs-Signature", hex.EncodeToString(sig.Sum(nil)))
	router.ServeHTTP(w, r)
	os.RemoveAll(filepath.Join(srvcfg.Dir.Tokens, "by-repo"))
	time.Sleep(5 * time.Second) //TODO HACK
	status := w.Code
	if status != http.StatusOK {
		t.Fatalf("Validate(w http.ResponseWriter, r *http.Request) status code = %d", status)
	}
}
*/
