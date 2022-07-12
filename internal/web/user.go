package web

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/G-Node/gin-cli/ginclient"
	gcfg "github.com/G-Node/gin-cli/ginclient/config"
	glog "github.com/G-Node/gin-cli/ginclient/log"
	"github.com/G-Node/gin-cli/git"
	gweb "github.com/G-Node/gin-cli/web"
	"github.com/G-Node/gin-valid/internal/config"
	"github.com/G-Node/gin-valid/internal/helpers"
	"github.com/G-Node/gin-valid/internal/log"
	"github.com/G-Node/gin-valid/internal/resources/templates"
	gogs "github.com/gogits/go-gogs-client"
	"github.com/gorilla/mux"
)

type repoHooksInfo struct {
	gogs.Repository
	Hooks map[string]ginhook
}

type ginhook struct {
	Validator string
	ID        int64
	State     hookstate
}

type hookstate uint8

const (
	hookenabled hookstate = iota
	hookdisabled
	hookunauthed
	hookbadconf
	hooknone
)

func cookieExp() time.Time {
	return time.Now().Add(7 * 24 * time.Hour)
}

func makeSessionKey(gcl *ginclient.Client, keyname string) error {
	keyPair, err := git.MakeKeyPair()
	if err != nil {
		return err
	}

	description := fmt.Sprintf("GIN Valid: %s", keyname)
	pubkey := fmt.Sprintf("%s %s", strings.TrimSpace(keyPair.Public), description)
	err = gcl.AddKey(pubkey, description, true)
	if err != nil {
		return err
	}

	configpath, err := gcfg.Path(true)
	if err != nil {
		log.Write("Could not create config directory for private key")
		return err
	}
	keyfilepath := filepath.Join(configpath, fmt.Sprintf("%s.key", keyname))
	ioutil.WriteFile(keyfilepath, []byte(keyPair.Private), 0600)

	return nil
}

func deleteSessionKey(gcl *ginclient.Client, keyname string) {
	description := fmt.Sprintf("GIN Valid: %s", keyname)
	gcl.DeletePubKeyByTitle(description)
	configpath, _ := gcfg.Path(false)
	keyfilepath := filepath.Join(configpath, fmt.Sprintf("%s.key", keyname))
	os.Remove(keyfilepath)
}

// generateNewSessionID simply generates a secure random 64-byte string (b64 encoded)
func generateNewSessionID() (string, error) {
	length := 64
	id := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		// This will bubble up and result in an authentication failure. Is
		// there a better message to display to the user? Perhaps 500?
		log.Write("[error] Failed to generate random session ID")
		return "", err
	}
	return base64.StdEncoding.EncodeToString(id), nil
}

func doLogin(username, password string) (string, error) {
	gincl := ginclient.New(serveralias)
	glog.Init()
	cfg := config.Read()
	clientID := cfg.Settings.ClientID

	// retrieve user's active tokens
	log.Write("Retrieving tokens for user '%s'", username)
	tokens, err := gincl.GetTokens(username, password)
	if err != nil {
		return "", err
	}

	// check if we have a gin-valid token
	log.Write("Checking for existing token")
	for _, token := range tokens {
		if token.Name == clientID {
			// found our token
			gincl.UserToken.Username = username
			gincl.UserToken.Token = token.Sha1
			log.Write("Found %s access token", clientID)
			break
		}
	}

	if len(gincl.UserToken.Token) == 0 {
		// no existing token; creating new one
		log.Write("Requesting new token from server")
		glog.Write("Performing login from gin-valid")
		err = gincl.NewToken(username, password, clientID)
		if err != nil {
			return "", err
		}
		log.Write("Login successful. Username: %s", username)
	}

	err = saveToken(gincl.UserToken)
	if err != nil {
		return "", err
	}

	sessionid, err := generateNewSessionID()
	if err != nil {
		return "", err
	}

	// link session ID to usertoken
	err = linkToSession(username, sessionid)
	return sessionid, err
}

// LoginGet renders the login form
func LoginGet(w http.ResponseWriter, r *http.Request) {
	loginForm(w, r, "")
}

// loginForm renders the login form
func loginForm(w http.ResponseWriter, r *http.Request, errMsg string) {
	log.Write("Login page")
	tmpl := template.New("layout")
	tmpl, err := tmpl.Parse(templates.Layout)
	if err != nil {
		log.Write("[Error] failed to parse html layout page")
		fail(w, r, http.StatusInternalServerError, "something went wrong")
		return
	}
	tmpl, err = tmpl.Parse(templates.Login)
	if err != nil {
		log.Write("[Error] failed to render login page")
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

// LoginPost logs in the user to the GIN server, storing a session token.
func LoginPost(w http.ResponseWriter, r *http.Request) {
	log.Write("Doing login")
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		log.Write("[error] Invalid form data")
		loginForm(w, r, "Authentication failed")
		return
	}
	sessionid, err := doLogin(username, password)
	if err != nil {
		log.Write("[error] Login failed: %s", err.Error())
		loginForm(w, r, "Authentication failed")
		return
	}

	cfg := config.Read()
	cookie := http.Cookie{
		Name:    cfg.Settings.CookieName,
		Value:   sessionid,
		Expires: cookieExp(),
		Secure:  false, // TODO: Switch when we go live
	}
	http.SetCookie(w, &cookie)
	// Redirect to repo listing
	http.Redirect(w, r, fmt.Sprintf("/repos/%s", username), http.StatusFound)
}

// Logout logouts the current user
func Logout(w http.ResponseWriter, r *http.Request) {
	cfg := config.Read()
	cookie := http.Cookie{
		Name:    cfg.Settings.CookieName,
		Value:   "",
		Expires: time.Time{},
		Secure:  false, // TODO: Switch when we go live
	}
	if conn, ok := websockets[cookie.Value]; ok {
		conn.Close()
		delete(websockets, cookie.Value)
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func getLoggedUserName(r *http.Request) string {
	cfg := config.Read()
	cookie, err := r.Cookie(cfg.Settings.CookieName)
	if err != nil {
		return ""
	}
	usertoken, err := getTokenBySession(cookie.Value)
	if err != nil {
		return ""
	}
	return usertoken.Username
}

func getSessionOrRedirect(w http.ResponseWriter, r *http.Request) (gweb.UserToken, error) {
	cfg := config.Read()
	cookie, err := r.Cookie(cfg.Settings.CookieName)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return gweb.UserToken{}, fmt.Errorf("no session cookie found")
	}
	usertoken, err := getTokenBySession(cookie.Value)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		log.Write("[Error] Loading token failed: %s", err.Error())
		return gweb.UserToken{}, fmt.Errorf("invalid session found in cookie")
	}
	return usertoken, nil
}

// ListRepos queries the GIN server for a list of repositories owned (or
// accessible) by a given user and renders the page which displays the
// repositories and their validation status.
func ListRepos(w http.ResponseWriter, r *http.Request) {
	ut, err := getSessionOrRedirect(w, r)
	if err != nil {
		log.Write("[Info] %s: Redirecting to login", err.Error())
		return
	}

	vars := mux.Vars(r)
	user, ok := vars["user"]
	if !ok {
		// redirect to logged in user
		user = ut.Username
		http.Redirect(w, r, fmt.Sprintf("/repos/%s", user), http.StatusFound)
		return
	}
	cl := ginclient.New(serveralias)
	cl.UserToken = ut

	userrepos, err := cl.ListRepos(user)
	if err != nil {
		log.ShowWrite("[Error] ListRepos failed: %s", err.Error())
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
		return
	}

	fmt.Printf("Got %d repos\n", len(userrepos))
	tmpl := template.New("layout")
	funcmap := map[string]interface{}{
		"ToLower": strings.ToLower,
		"ToUpper": strings.ToUpper,
	}
	tmpl.Funcs(funcmap)
	tmpl, err = tmpl.Parse(templates.Layout)
	if err != nil {
		log.Write("[Error] failed to parse html layout page")
		fail(w, r, http.StatusInternalServerError, "something went wrong")
		return
	}
	tmpl, err = tmpl.Parse(templates.RepoList)
	if err != nil {
		log.Write("[Error] failed to render repository list page: %s", err.Error())
		fail(w, r, http.StatusInternalServerError, "something went wrong")
		return
	}
	reposActive := make([]repoHooksInfo, 0, len(userrepos))
	reposInactive := make([]repoHooksInfo, 0, len(userrepos))

	checkActive := func(rhinfo repoHooksInfo) bool {
		// If at least one hook is not hooknone, return true
		for _, hook := range rhinfo.Hooks {
			if hook.State != hooknone {
				return true
			}
		}
		return false
	}

	// TODO: Enum for hook states (see issue #5)
	for _, rinfo := range userrepos {
		repohooks, err := getRepoHooks(cl, rinfo.FullName)
		if err != nil {
			// simply initialise the map for now
			repohooks = make(map[string]ginhook)
		}
		rhinfo := repoHooksInfo{rinfo, repohooks}
		if checkActive(rhinfo) {
			reposActive = append(reposActive, rhinfo)
		} else {
			reposInactive = append(reposInactive, rhinfo)
		}
	}
	year, _, _ := time.Now().Date()
	loggedUsername := getLoggedUserName(r)
	srvcfg := config.Read()
	allrepos := struct {
		Active      []repoHooksInfo
		Inactive    []repoHooksInfo
		GinURL      string
		CurrentYear int
		UserName    string
	}{
		reposActive,
		reposInactive,
		srvcfg.GINAddresses.WebURL,
		year,
		loggedUsername,
	}
	tmpl.Execute(w, &allrepos)
}

// matchValidator receives a URL path from a GIN hook and returns the validator
// it specifies.
func matchValidator(path string) (string, error) {
	re := regexp.MustCompile(`validate/(?P<validator>[^/]+)/.*`)
	if !re.MatchString(path) {
		return "", fmt.Errorf("URL does not match expected pattern for validator hooks")
	}
	match := re.FindStringSubmatch(path)
	validator := match[1]

	if !helpers.SupportedValidator(validator) {
		return "", fmt.Errorf("URL matches pattern but validator '%s' is not known", validator)
	}

	return validator, nil
}

// getRepoHooks queries the main GIN server and determines which validators are
// enabled via hooks (true), which are configured but disabled (false)
func getRepoHooks(cl *ginclient.Client, repopath string) (map[string]ginhook, error) {
	// fetch all hooks
	res, err := cl.Get(path.Join("api", "v1", "repos", repopath, "hooks"))
	if err != nil {
		// Bad request?
		log.Write("hook request failed for %s", repopath)
		return nil, fmt.Errorf("hook request failed")
	}
	if res.StatusCode != http.StatusOK {
		// Bad repo path? Unauthorised request?
		log.Write("hook request for %s returned non-OK exit status: %s", repopath, res.Status)
		return nil, fmt.Errorf("hook request returned non-OK exit status: %s", res.Status)
	}
	var gogshooks []gogs.Hook
	defer gweb.CloseRes(res.Body)
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		// failed to read response body
		log.Write("failed to read response for %s", repopath)
		return nil, fmt.Errorf("failed to read response")
	}
	err = json.Unmarshal(b, &gogshooks)
	if err != nil {
		// failed to parse response body
		log.Write("failed to parse hooks list for %s", repopath)
		return nil, fmt.Errorf("failed to parse hooks list")
	}

	hooks := make(map[string]ginhook)
	for _, hook := range gogshooks {
		// parse URL to get validator
		hookurl, err := url.Parse(hook.Config["url"])
		if err != nil {
			// can't parse URL. Ignore
			log.Write("can't parse URL %s", hook.Config["url"])
			continue
		}
		validator, err := matchValidator(hookurl.Path)
		if err != nil {
			// Validator not recognised (either path was bad or validator is
			// not supported). Either way, just continue.
			log.Write("validator in path not recognised %s (%s)", hookurl.String(), hookurl.Path)
			log.Write("hook URL in config: %s", hook.Config["url"])
			log.Write(err.Error())
			continue
		}
		// Check if Active, and 'push' is in Events
		var pushenabled bool
		for _, event := range hook.Events {
			if event == "push" {
				pushenabled = true
				break
			}
		}
		var state hookstate
		if hook.Active && pushenabled {
			log.Write("found %s hook for %s", validator, repopath)
			state = hookenabled
		} else {
			log.Write("found disabled or invalid %s hook for %s", validator, repopath)
			state = hookdisabled
		}
		hooks[validator] = ginhook{validator, hook.ID, state}
		// TODO: Check if the same validator is found twice
	}
	// add supported validators that were not found and mark them hooknone
	supportedValidators := config.Read().Settings.Validators
	for _, validator := range supportedValidators {
		if _, ok := hooks[validator]; !ok {
			hooks[validator] = ginhook{validator, -1, hooknone}
		}
	}
	return hooks, nil
}

// ShowRepo renders the repository information page where the user can enable or
// disable validator hooks.
func ShowRepo(w http.ResponseWriter, r *http.Request) {
	ut, err := getSessionOrRedirect(w, r)
	if err != nil {
		log.Write("[Info] %s: Redirecting to login", err.Error())
		return
	}

	vars := mux.Vars(r)
	user := vars["user"]
	repo := vars["repo"]
	repopath := fmt.Sprintf("%s/%s", user, repo)
	cl := ginclient.New(serveralias)
	cl.UserToken = ut
	fmt.Printf("Requesting repository info %s\n", repopath)
	fmt.Printf("Server alias: %s\n", serveralias)
	fmt.Println("Server configuration:")
	fmt.Println(cl.Host)

	repoinfo, err := cl.GetRepo(repopath)
	if err != nil {
		log.ShowWrite("[Error] Repo info failed: %s", err.Error())
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
		return
	}

	tmpl := template.New("layout")
	funcmap := map[string]interface{}{
		"ToLower": strings.ToLower,
		"ToUpper": strings.ToUpper,
	}
	tmpl.Funcs(funcmap)
	tmpl, err = tmpl.Parse(templates.Layout)
	if err != nil {
		log.Write("[Error] failed to parse html layout page")
		fail(w, r, http.StatusInternalServerError, "something went wrong")
		return
	}
	tmpl, err = tmpl.Parse(templates.RepoPage)
	if err != nil {
		log.Write("[Error] failed to render repository page: %s", err.Error())
		fail(w, r, http.StatusInternalServerError, "something went wrong")
		return
	}

	hooks, err := getRepoHooks(cl, repopath)
	if err != nil {
		hooks = make(map[string]ginhook)
	}
	year, _, _ := time.Now().Date()
	loggedUsername := getLoggedUserName(r)
	srvcfg := config.Read()
	repohi := struct {
		gogs.Repository
		Hooks       map[string]ginhook
		GinURL      string
		CurrentYear int
		UserName    string
	}{
		repoinfo,
		hooks,
		srvcfg.GINAddresses.WebURL,
		year,
		loggedUsername,
	}
	tmpl.Execute(w, &repohi)
}
