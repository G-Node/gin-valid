package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/G-Node/gin-cli/ginclient"
	gweb "github.com/G-Node/gin-cli/web"
	"github.com/G-Node/gin-valid/config"
	"github.com/G-Node/gin-valid/helpers"
	"github.com/G-Node/gin-valid/log"
	gogs "github.com/gogits/go-gogs-client"
	"github.com/gorilla/mux"
)

func EnableHook(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		return
	}
	vars := mux.Vars(r)
	user := vars["user"]
	repo := vars["repo"]
	validator := strings.ToLower(vars["validator"])
	ut, err := getSessionOrRedirect(w, r)
	if err != nil {
		return
	}
	if !helpers.SupportedValidator(validator) {
		fail(w, http.StatusNotFound, "unsupported validator")
		return
	}
	repopath := fmt.Sprintf("%s/%s", user, repo)
	err = createValidHook(repopath, validator, ut)
	if err != nil {
		// TODO: Check if failure is for other reasons and maybe return 500 instead
		fail(w, http.StatusUnauthorized, err.Error())
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/repos/%s", ut.Username), http.StatusFound)
}

func DisableHook(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		return
	}
	vars := mux.Vars(r)
	user := vars["user"]
	repo := vars["repo"]
	hookidstr := vars["hookid"]

	hookid, err := strconv.Atoi(hookidstr)
	if err != nil {
		// bad hook ID (not a number): throw a generic 404
		fail(w, http.StatusNotFound, "not found")
		return
	}

	ut, err := getSessionOrRedirect(w, r)
	if err != nil {
		return
	}

	repopath := fmt.Sprintf("%s/%s", user, repo)
	err = deleteValidHook(repopath, hookid, ut)
	if err != nil {
		// TODO: Check if failure is for other reasons and maybe return 500 instead
		fail(w, http.StatusUnauthorized, err.Error())
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/repos/%s", ut.Username), http.StatusFound)
}

func checkHookSecret(data []byte, secret string) bool {
	cfg := config.Read()
	hooksecret := cfg.Settings.HookSecret
	sig := hmac.New(sha256.New, []byte(hooksecret))
	sig.Write(data)
	signature := hex.EncodeToString(sig.Sum(nil))
	return signature == secret
}

func createValidHook(repopath string, validator string, usertoken gweb.UserToken) error {
	// TODO: AVOID DUPLICATES:
	//   - If it's already hooked and we have it on record, do nothing
	//   - If it's already hooked, but we don't know about it, check if it's valid and don't recreate
	log.Write("Adding %s hook to %s\n", validator, repopath)

	cfg := config.Read()
	client := ginclient.New(serveralias)
	client.UserToken = usertoken
	hookconfig := make(map[string]string)
	hooksecret := cfg.Settings.HookSecret

	host := fmt.Sprintf("%s:%s", cfg.Settings.RootURL, cfg.Settings.Port)
	u, err := url.Parse(host)
	u.Path = path.Join(u.Path, "validate", validator, repopath)
	hookconfig["url"] = u.String()
	hookconfig["content_type"] = "json"
	hookconfig["secret"] = hooksecret
	data := gogs.CreateHookOption{
		Type:   "gogs",
		Config: hookconfig,
		Active: true,
		Events: []string{"push"},
	}
	res, err := client.Post(fmt.Sprintf("/api/v1/repos/%s/hooks", repopath), data)
	if err != nil {
		log.Write("[error] failed to post: %s", err.Error())
		return fmt.Errorf("Hook creation failed: %s", err.Error())
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		log.Write("[error] non-OK response: %s", res.Status)
		return fmt.Errorf("Hook creation failed: %s", res.Status)
	}

	// link user token to repository name so we can use it for validation
	return linkToRepo(usertoken.Username, repopath)
}

func deleteValidHook(repopath string, id int, usertoken gweb.UserToken) error {
	log.Write("Deleting %d from %s\n", id, repopath)

	client := ginclient.New(serveralias)
	client.UserToken = usertoken

	res, err := client.Delete(fmt.Sprintf("/api/v1/repos/%s/hooks/%d", repopath, id))
	if err != nil {
		log.Write("[error] bad response from server %s", err.Error())
		return err
	}
	defer res.Body.Close()
	log.Write("[info] removed hook for %s", repopath)

	log.Write("[info] removing repository -> token link")
	err = rmTokenRepoLink(repopath)
	if err != nil {
		log.Write("[error] failed to delete token link: %s", err.Error())
		// don't fail
	}

	return nil
}
