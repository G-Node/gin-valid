package web

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"
	"github.com/mpsonntag/gin-valid/config"
	"github.com/mpsonntag/gin-valid/log"
)

// Results returns the results of a previously run BIDS validation.
func Results(w http.ResponseWriter, r *http.Request) {
	user := mux.Vars(r)["user"]
	repo := mux.Vars(r)["repo"]
	log.Write("[Info] results for repo '%s/%s'\n", user, repo)

	srvcfg := config.Read()
	fp := filepath.Join(srvcfg.Dir.Result, user, repo, srvcfg.Label.ResultsFolder, srvcfg.Label.ResultsFile)
	content, err := ioutil.ReadFile(fp)
	if err != nil {
		log.Write("[Error] serving '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("404 Nothing to see here...")))
		return
	}

	var parseBIDS BidsRoot
	err = json.Unmarshal(content, &parseBIDS)
	if err != nil {
		log.Write("[Error] unmarshalling '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}

	http.ServeContent(w, r, "results", time.Now(), bytes.NewReader(content))
}
