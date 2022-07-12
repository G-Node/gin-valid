package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/G-Node/gin-cli/ginclient"
	glog "github.com/G-Node/gin-cli/ginclient/log"
	"github.com/G-Node/gin-cli/git"
	"github.com/G-Node/gin-valid/internal/config"
	"github.com/G-Node/gin-valid/internal/helpers"
	"github.com/G-Node/gin-valid/internal/log"
	"github.com/G-Node/gin-valid/internal/resources"
	"github.com/G-Node/gin-valid/internal/resources/templates"
	gogs "github.com/gogits/go-gogs-client"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// BidsMessages contains Errors, Warnings and Ignored messages.
// Currently its just the number of individual messages
// we are interested in. If this changes, the messages
// will be expanded into proper structs of their own.
type BidsMessages struct {
	Errors   []interface{} `json:"errors"`
	Warnings []interface{} `json:"warnings"`
	Ignored  []interface{} `json:"ignored"`
}

// BidsRoot contains only the root issues element.
type BidsRoot struct {
	Issues BidsMessages `json:"issues"`
}

// Validationcfg is used to unmarshall a config file
// holding information specific for running the
// various validations. e.g. where the root
// folder of a bids directory can be found or
// whether the NiftiHeaders should be ignored.
type Validationcfg struct {
	Bidscfg struct {
		BidsRoot      string `yaml:"bidsroot"`
		ValidateNifti bool   `yaml:"validatenifti"`
	} `yaml:"bidsconfig"`
}

var websockets map[string]*websocket.Conn = make(map[string]*websocket.Conn)

// handleValidationConfig unmarshalles a yaml config file
// from file and returns the resulting Validationcfg struct.
func handleValidationConfig(cfgpath string) (Validationcfg, error) {
	valcfg := Validationcfg{}

	content, err := ioutil.ReadFile(cfgpath)
	if err != nil {
		return valcfg, err
	}

	err = yaml.Unmarshal(content, &valcfg)
	if err != nil {
		return valcfg, err
	}

	return valcfg, nil
}

// validateBIDS runs the BIDS validator on the specified repository in 'path'
// and saves the results to the appropriate document for later viewing.
func validateBIDS(valroot, resdir string) error {
	srvcfg := config.Read()
	// Use validation config file if available
	var validateNifti bool

	cfgpath := filepath.Join(valroot, srvcfg.Label.ValidationConfigFile)
	log.ShowWrite("[Info] looking for config file at '%s'", cfgpath)
	if fi, err := os.Stat(cfgpath); err == nil && !fi.IsDir() {
		valcfg, err := handleValidationConfig(cfgpath)
		if err == nil {
			checkdir := filepath.Join(valroot, valcfg.Bidscfg.BidsRoot)
			if fi, err = os.Stat(checkdir); err == nil && fi.IsDir() {
				valroot = checkdir
				log.ShowWrite("[Info] using validation root directory: %s\n%s", valroot, checkdir)
			} else {
				log.ShowWrite("[Error] reading validation root directory: %s", err.Error())
			}
			validateNifti = valcfg.Bidscfg.ValidateNifti
		} else {
			log.ShowWrite("[Error] unmarshalling validation config file: %s", err.Error())
		}
	} else {
		log.ShowWrite("[Info] no validation config file found or processed, running from repo root (%s)", err.Error())
	}

	// Ignoring NiftiHeaders for now, since it seems to be a common error
	outBadge := filepath.Join(resdir, srvcfg.Label.ResultsBadge)
	log.ShowWrite("[Info] Running bids validation: '%s %t --json %s'", srvcfg.Exec.BIDS, validateNifti, valroot)

	// Make sure the validator arguments are in the right order
	var args []string
	if !validateNifti {
		args = append(args, "--ignoreNiftiHeaders")
	}
	args = append(args, "--json")
	args = append(args, valroot)

	// cmd = exec.Command(srvcfg.Exec.BIDS, validateNifti, "--json", valroot)
	var out, serr bytes.Buffer
	cmd := exec.Command(srvcfg.Exec.BIDS, args...)
	out.Reset()
	serr.Reset()
	cmd.Stdout = &out
	cmd.Stderr = &serr
	// cmd.Dir = tmpdir
	if err := cmd.Run(); err != nil {
		err = fmt.Errorf("[Error] running bids validation (%s): '%s', '%s'", valroot, err.Error(), serr.String())
		log.ShowWrite(err.Error())
		return err
	}

	// We need this for both the writing of the result and the badge
	output := out.Bytes()

	// CHECK: can this lead to a race condition, if a job for the same user/repo combination is started twice in short succession?
	outFile := filepath.Join(resdir, srvcfg.Label.ResultsFile)
	err := ioutil.WriteFile(outFile, []byte(output), os.ModePerm)
	if err != nil {
		err = fmt.Errorf("[Error] writing results file for %q", valroot)
		log.ShowWrite(err.Error())
		return err
	}

	// Write proper badge according to result
	content := resources.SuccessBadge
	var parseBIDS BidsRoot
	err = json.Unmarshal(output, &parseBIDS)
	if err != nil {
		err = fmt.Errorf("[Error] unmarshalling results json: %s", err.Error())
		log.ShowWrite(err.Error())
		return err
	}

	if len(parseBIDS.Issues.Errors) > 0 {
		content = resources.ErrorBadge
	} else if len(parseBIDS.Issues.Warnings) > 0 {
		content = resources.WarningBadge
	}

	err = ioutil.WriteFile(outBadge, []byte(content), os.ModePerm)
	if err != nil {
		err = fmt.Errorf("[Error] writing results badge for %q", valroot)
		log.ShowWrite(err.Error())
		return err
	}

	log.ShowWrite("[Info] finished validating repo at %q", valroot)
	return nil
}

// validateNIX runs the NIX validator on the specified repository in 'path'
// and saves the results to the appropriate document for later viewing.
func validateNIX(valroot, resdir string) error {
	srvcfg := config.Read()

	// TODO: Allow validator config that specifies file paths to validate
	// For now we validate everything
	nixargs := make([]string, 0)
	nixargs = append(nixargs, "validate")
	// Find all NIX files (.nix) in the repository
	nixfinder := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// something went wrong; log this and continue
			log.ShowWrite("[Error] NIXFinder directory walk caused error at %q: %s", path, err.Error())
			return nil
		}

		// Skip git directory
		if info.Name() == ".git" {
			return filepath.SkipDir
		}

		if info.IsDir() {
			// nothing to do; continue
			return nil
		}

		if strings.ToLower(filepath.Ext(path)) == ".nix" {
			nixargs = append(nixargs, path)
		}
		return nil
	}

	err := filepath.Walk(valroot, nixfinder)
	if err != nil {
		err = fmt.Errorf("[Error] while looking for NIX files in repository at %q: %s", valroot, err.Error())
		log.ShowWrite(err.Error())
		return err
	}

	outBadge := filepath.Join(resdir, srvcfg.Label.ResultsBadge)

	var out, serr bytes.Buffer
	cmd := exec.Command(srvcfg.Exec.NIX, nixargs...)
	out.Reset()
	serr.Reset()
	cmd.Stdout = &out
	cmd.Stderr = &serr
	// cmd.Dir = tmpdir
	if err = cmd.Run(); err != nil {
		err = fmt.Errorf("[Error] running NIX validation (%s): '%s', '%s'", valroot, err.Error(), serr.String())
		log.ShowWrite(err.Error())
		return err
	}

	// We need this for both the writing of the result and the badge
	errtag := []byte("with errors")
	warntag := []byte("with warnings")
	var badge []byte
	output := out.Bytes()
	switch {
	case bytes.Contains(output, errtag):
		badge = []byte(resources.ErrorBadge)
	case bytes.Contains(output, warntag):
		badge = []byte(resources.WarningBadge)
	default:
		badge = []byte(resources.SuccessBadge)
	}

	// CHECK: can this lead to a race condition, if a job for the same user/repo combination is started twice in short succession?
	outFile := filepath.Join(resdir, srvcfg.Label.ResultsFile)
	err = ioutil.WriteFile(outFile, output, os.ModePerm)
	if err != nil {
		err = fmt.Errorf("[Error] writing results file for %q", valroot)
		log.ShowWrite(err.Error())
		return err
	}

	err = ioutil.WriteFile(outBadge, badge, os.ModePerm)
	if err != nil {
		err = fmt.Errorf("[Error] writing results badge for %q", valroot)
		log.ShowWrite(err.Error())
		return err
	}

	log.ShowWrite("[Info] finished validating repo at %q", valroot)
	return nil
}

func validateODML(valroot, resdir string) error {
	srvcfg := config.Read()

	// TODO: Allow validator config that specifies file paths to validate
	// For now we validate everything
	odmlfiles := make([]string, 0)
	// Find all NIX files (.nix) in the repository
	odmlfinder := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// something went wrong; log this and continue
			log.ShowWrite("[Error] ODMLFinder directory walk caused error at %q: %s", path, err.Error())
			return nil
		}
		if info.IsDir() {
			// nothing to do; continue
			return nil
		}

		// Skip git directory
		if info.Name() == ".git" {
			return filepath.SkipDir
		}

		extension := strings.ToLower(filepath.Ext(path))
		if extension == ".odml" || extension == ".xml" {
			odmlfiles = append(odmlfiles, path)
		}
		return nil
	}

	err := filepath.Walk(valroot, odmlfinder)
	if err != nil {
		err = fmt.Errorf("[Error] while looking for odML files in repository at %q: %s", valroot, err.Error())
		log.ShowWrite(err.Error())
		return err
	}

	outBadge := filepath.Join(resdir, srvcfg.Label.ResultsBadge)

	var out, serr bytes.Buffer
	cmd := exec.Command(srvcfg.Exec.ODML, odmlfiles...)
	out.Reset()
	serr.Reset()
	cmd.Stdout = &out
	cmd.Stderr = &serr
	if err = cmd.Run(); err != nil {
		err = fmt.Errorf("[Error] running odML validation (%s): '%s', '%s'", valroot, err.Error(), serr.String())
		log.ShowWrite(err.Error())
		return err
	}

	// We need this for both the writing of the result and the badge
	errtag := []byte("[error]")
	warntag := []byte("[warning]")
	fataltag := []byte("[fatal]")
	var badge []byte
	output := out.Bytes()
	switch {
	case bytes.Contains(output, errtag) || bytes.Contains(output, fataltag):
		badge = []byte(resources.ErrorBadge)
	case bytes.Contains(output, warntag):
		badge = []byte(resources.WarningBadge)
	default:
		badge = []byte(resources.SuccessBadge)
	}

	// CHECK: can this lead to a race condition, if a job for the same user/repo combination is started twice in short succession?
	outFile := filepath.Join(resdir, srvcfg.Label.ResultsFile)
	err = ioutil.WriteFile(outFile, output, os.ModePerm)
	if err != nil {
		err = fmt.Errorf("[Error] writing results file for %q", valroot)
		log.ShowWrite(err.Error())
		return err
	}

	err = ioutil.WriteFile(outBadge, badge, os.ModePerm)
	if err != nil {
		err = fmt.Errorf("[Error] writing results badge for %q", valroot)
		log.ShowWrite(err.Error())
		return err
	}

	log.ShowWrite("[Info] finished validating repo at %q", valroot)
	return nil
}

func runValidatorBoth(validator, repopath, commit, commitname string, gcl *ginclient.Client, automatic bool, r *http.Request) string {
	respath := filepath.Join(validator, repopath, commit)
	go func() {
		log.ShowWrite("[Info] Running %s validation on repository %q (%s)", validator, repopath, commitname)

		// TODO add check if a repo is currently being validated. Since the cloning
		// can potentially take quite some time prohibit running the same
		// validation at the same time. Could also move this to a mapped go
		// routine and if the same repo is validated twice, the first occurrence is
		// stopped and cleaned up while the second starts anew - to make sure its
		// always the latest state of the repository that is being validated.

		// TODO: Use the payload data to check if the specific commit has already
		// been validated
		srvcfg := config.Read()
		resdir := filepath.Join(srvcfg.Dir.Result, respath)

		// Create results folder if necessary
		// CHECK: can this lead to a race condition, if a job for the same user/repo combination is started twice in short succession?
		err := os.MkdirAll(resdir, os.ModePerm)
		if err != nil {
			log.ShowWrite("[Error] creating %q results folder: %s", resdir, err.Error())
			return
		}

		tmpdir, err := ioutil.TempDir(srvcfg.Dir.Temp, validator)
		if err != nil {
			log.ShowWrite("[Error] Internal error: Couldn't create temporary gin directory: %s", err.Error())
			writeValFailure(resdir)
			return
		}

		repopathparts := strings.SplitN(repopath, "/", 2)
		_, repo := repopathparts[0], repopathparts[1]
		valroot := filepath.Join(tmpdir, repo)

		// Enable cleanup once tried and tested
		defer os.RemoveAll(tmpdir)

		// Add the processing badge and message to display while the validator runs
		procBadge := filepath.Join(resdir, srvcfg.Label.ResultsBadge)
		err = ioutil.WriteFile(procBadge, []byte(resources.ProcessingBadge), os.ModePerm)
		if err != nil {
			log.ShowWrite("[Error] writing results badge for %q", valroot)
		}

		outFile := filepath.Join(resdir, srvcfg.Label.ResultsFile)
		err = ioutil.WriteFile(outFile, []byte(progressmsg), os.ModePerm)
		if err != nil {
			log.ShowWrite("[Error] writing results file for %q", valroot)
		}

		if automatic { //TODO should be automatic or not?
			// Link 'latest' to new res dir to show processing
			latestdir := filepath.Join(filepath.Dir(resdir), "latest")
			os.Remove(latestdir) // ignore error
			err = os.Symlink(resdir, latestdir)
			if err != nil {
				log.ShowWrite("[Error] failed to link %q to %q: %s", resdir, latestdir, err.Error())
				// Don't return if processing badge write fails
			}
			err = makeSessionKey(gcl, commit)
			if err != nil {
				log.ShowWrite("[error] failed to create session key: %s", err.Error())
				writeValFailure(resdir)
				return
			}
			defer deleteSessionKey(gcl, commit)
		}
		// TODO: if (annexed) content is not available yet, wait and retry.  We
		// would have to set a max timeout for this.  The issue is that when a user
		// does a 'gin upload' a push happens immediately and the hook is
		// triggered, but annexed content is only transferred after the push and
		// could take a while (hours?). The validation service should try to
		// download content after the transfer is complete, or should keep retrying
		// until it's available, with a timeout. We could also make it more
		// efficient by only downloading the content in the directories which are
		// specified in the validator config (if it exists).

		glog.Init()
		clonechan := make(chan git.RepoFileStatus)
		pth, _ := os.Getwd()
		os.Chdir(tmpdir)
		go gcl.CloneRepo(repopath, clonechan)
		for stat := range clonechan {
			if stat.Err != nil && stat.Err.Error() != "Error initialising local directory" {
				log.ShowWrite("[Error] Failed to fetch repository data for %q: %s", repopath, stat.Err.Error())
				writeValFailure(resdir)
				return
			}
			log.ShowWrite("[Info] %s %s", stat.State, stat.Progress)
		}
		log.ShowWrite("[Info] clone complete for '%s'", repopath)

		if automatic {
			// checkout specific commit then download all content
			log.ShowWrite("[Info] git checkout %s", commit)
			err = git.Checkout(commit, nil)
			if err != nil {
				log.ShowWrite("[Error] failed to checkout commit %q: %s", commit, err.Error())
				writeValFailure(resdir)
				return
			}
		}
		log.ShowWrite("[Info] Downloading content")
		getcontentchan := make(chan git.RepoFileStatus)
		// TODO: Get only the content for the files that will be validated
		go gcl.GetContent([]string{"."}, getcontentchan)
		for stat := range getcontentchan {
			if stat.Err != nil {
				log.ShowWrite("[Error] failed to get content for %q: %s", repopath, stat.Err.Error())
				writeValFailure(resdir)
				return
			}
			log.ShowWrite("[Info] %s %s %s", stat.State, stat.FileName, stat.Progress)
		}
		log.ShowWrite("[Info] get-content complete")
		os.Chdir(pth)

		switch validator {
		case "bids":
			err = validateBIDS(valroot, resdir)
		case "nix":
			err = validateNIX(valroot, resdir)
		case "odml":
			err = validateODML(valroot, resdir)
		default:
			err = fmt.Errorf("[Error] invalid validator name: %s", validator)
		}

		if err != nil {
			writeValFailure(resdir)
		}
		cookie, _ := r.Cookie(srvcfg.Settings.CookieName)
		websockets[cookie.Value].WriteMessage(websocket.TextMessage, []byte("REFRESH"))
	}()
	return respath
}
func runValidator(validator, repopath, commit string, gcl *ginclient.Client, r *http.Request) {
	automatic := true
	runValidatorBoth(validator, repopath, commit, commit, gcl, automatic, r)
}

func runValidatorPub(validator, repopath string, gcl *ginclient.Client, r *http.Request) string {
	automatic := false
	return runValidatorBoth(validator, repopath, uuid.New().String(), "HEAD", gcl, automatic, r)
}

// writeValFailure writes a badge and page content for when a hook payload is
// valid, but the validator failed to run.  This function does not return
// anything, but logs all errors.
func writeValFailure(resdir string) {
	log.ShowWrite("[Error] VALIDATOR RUN FAILURE")
	srvcfg := config.Read()
	procBadge := filepath.Join(resdir, srvcfg.Label.ResultsBadge)
	err := ioutil.WriteFile(procBadge, []byte(resources.FailureBadge), os.ModePerm)
	if err != nil {
		log.ShowWrite("[Error] writing error badge to %q: %s", resdir, err.Error())
	}

	outFile := filepath.Join(resdir, srvcfg.Label.ResultsFile)
	err = ioutil.WriteFile(outFile, []byte("ERROR: The validator failed to run"), os.ModePerm)
	if err != nil {
		log.ShowWrite("[Error] writing error page to %q: %s", resdir, err.Error())
	}
}

// Root handles the root path of the service. If the user is logged in, it
// redirects to the user's repository listing. If the user is not logged in, it
// redirects to the login form.
func Root(w http.ResponseWriter, r *http.Request) {
	// Since the /repos path does the same, let's just redirect to that
	http.Redirect(w, r, "/repos", http.StatusFound)
}

// PubValidateGet renders the one-time validation form, which allows the user
// to manually run a validator on a publicly accessible repository, without
// using a web hook.
func PubValidateGet(w http.ResponseWriter, r *http.Request) {
	renderValidationForm(w, r, "")
}

// renderValidationForm renders the one-time validation form, which allows the user
// to manually run a validator on a publicly accessible repository, without
// using a web hook.
func renderValidationForm(w http.ResponseWriter, r *http.Request, errMsg string) {
	tmpl := template.New("layout")
	tmpl, err := tmpl.Parse(templates.Layout)
	if err != nil {
		log.ShowWrite("[Error] failed to parse html layout page")
		fail(w, r, http.StatusInternalServerError, "something went wrong")
		return
	}
	tmpl, err = tmpl.Parse(templates.PubValidate)
	if err != nil {
		log.ShowWrite("[Error] failed to render root page")
		fail(w, r, http.StatusInternalServerError, "something went wrong")
		return
	}
	year, _, _ := time.Now().Date()
	loggedUsername := getLoggedUserName(r)
	srvcfg := config.Read()
	data := struct {
		GinURL       string
		CurrentYear  int
		ErrorMessage string
		UserName     string
	}{
		srvcfg.GINAddresses.WebURL,
		year,
		errMsg,
		loggedUsername,
	}
	tmpl.Execute(w, &data)
}

// Socket creates the websocket for async communication (refreshing the page)
func Socket(w http.ResponseWriter, r *http.Request) {
	srvcfg := config.Read()
	cookie, err := r.Cookie(srvcfg.Settings.CookieName)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "You are not logged in")
		return
	}
	var upgrader = websocket.Upgrader{}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fail(w, r, http.StatusServiceUnavailable, "Cannot open websocket")
		return
	}
	if conn, ok := websockets[cookie.Value]; ok {
		conn.Close()
	}
	websockets[cookie.Value] = conn
}

// PubValidatePost parses the POST data from the root form and calls the
// validator using the built-in ServiceWaiter.
func PubValidatePost(w http.ResponseWriter, r *http.Request) {
	srvcfg := config.Read()
	ginuser := srvcfg.Settings.GINUser

	r.ParseForm()
	repopath := r.Form["repopath"][0]
	validators := r.Form["validator"]
	if len(validators) < 1 {
		log.ShowWrite("[error] no validator selected")
		fail(w, r, http.StatusBadRequest, "No validator has been selected")
		return
	}
	validator := r.Form["validator"][0]

	log.ShowWrite("[Info] About to validate repository '%s' with %s", repopath, ginuser)
	log.ShowWrite("[Info] Logging in to GIN server")
	gcl := ginclient.New(serveralias)
	err := gcl.Login(ginuser, srvcfg.Settings.GINPassword, srvcfg.Settings.ClientID)
	if err != nil {
		log.ShowWrite("[error] failed to login as %s", ginuser)
		msg := fmt.Sprintf("failed to validate '%s': %s", repopath, err.Error())
		fail(w, r, http.StatusUnauthorized, msg)
		return
	}

	// check if repository is accessible
	repoinfo, err := gcl.GetRepo(repopath)
	if err != nil {
		renderValidationForm(w, r, fmt.Sprintf("Repository '%s' does not exist.", repopath))
		return
	}
	if repoinfo.Private {
		// We (the built in ServiceWaiter) have access, but the repository is
		// marked private. This can happen if an owner of the private
		// repository adds the user as a collaborator to the repository. We
		// don't allow this.
		fail(w, r, http.StatusNotFound, fmt.Sprintf("repository '%s' does not exist", repopath))
		return
	}

	respath := runValidatorPub(validator, repopath, gcl, r)
	http.Redirect(w, r, filepath.Join("results", respath), http.StatusFound)
}

// Validate temporarily clones a provided repository from
// a gin server and checks whether the content of the
// repository is a valid BIDS dataset.
// Any cloned files are cleaned up after the check is done.
func Validate(w http.ResponseWriter, r *http.Request) {
	log.ShowWrite("[Info] Entering validation")
	// TODO: Simplify/split this function
	secret := r.Header.Get("X-Gogs-Signature")

	var hookdata gogs.PushPayload
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.ShowWrite("[Error] failed to parse hook payload")
		fail(w, r, http.StatusBadRequest, "bad request")
		return
	}
	err = json.Unmarshal(b, &hookdata)
	if err != nil {
		log.ShowWrite("[Error] failed to parse hook payload")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
		return
	}
	if !checkHookSecret(b, secret) {
		log.ShowWrite("[Error] authorisation failed: bad secret")
		fail(w, r, http.StatusBadRequest, "bad request")
		return
	}

	commithash := hookdata.After

	log.ShowWrite("[Info] Hook secret: %s", secret)
	log.ShowWrite("[Info] Commit hash: %s", commithash)

	vars := mux.Vars(r)
	validator := vars["validator"]
	if !helpers.SupportedValidator(validator) {
		log.ShowWrite("[Error] unsupported validator (%v)", validator)
		fail(w, r, http.StatusNotFound, "unsupported validator")
		return
	}
	user := vars["user"]
	repo := vars["repo"]
	repopath := fmt.Sprintf("%s/%s", user, repo)
	log.ShowWrite("[Info] '%s' validation for repo '%s'", validator, repopath)

	// TODO add check if a repo is currently being validated. Since the cloning
	// can potentially take quite some time prohibit running the same
	// validation at the same time. Could also move this to a mapped go
	// routine and if the same repo is validated twice, the first occurrence is
	// stopped and cleaned up while the second starts anew - to make sure its
	// always the latest state of the repository that is being validated.

	// TODO: Use the payload data to check if the specific commit has already
	// been validated

	// get the token for this repository
	ut, err := getTokenByRepo(repopath)
	if err != nil {
		// We don't have a valid token for this repository: can't clone
		log.ShowWrite("[Error] Bad Token: %v", err)
		msg := fmt.Sprintf("accessing '%s': no access token found", repopath)
		fail(w, r, http.StatusUnauthorized, msg)
		return
	}
	log.ShowWrite("[Info] Using user %s", ut.Username)
	gcl := ginclient.New(serveralias)
	gcl.UserToken = ut

	// check if repository exists and is accessible
	_, err = gcl.GetRepo(repopath)
	if err != nil {
		fail(w, r, http.StatusNotFound, err.Error())
		return
	}

	log.ShowWrite("[Info] Got user %s. Checking repo", gcl.Username)
	// Payload is good. Run validator asynchronously and return OK header
	runValidator(validator, repopath, commithash, gcl, r)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
