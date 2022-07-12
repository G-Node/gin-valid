package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/G-Node/gin-valid/internal/config"
	"github.com/G-Node/gin-valid/internal/helpers"
	"github.com/G-Node/gin-valid/internal/log"
	"github.com/G-Node/gin-valid/internal/resources/templates"
	"github.com/gorilla/mux"
)

// ResultsHistoryStruct is the struct containing references to
// all validations already performed
type ResultsHistoryStruct struct {
	Results []Result
}

// Result is the struct containing info about a single
// validator run
type Result struct {
	Href  string
	Alt   string
	Text1 string
	Text2 string
	Badge template.HTML
}

// BidsResultStruct is the struct to parse a full BIDS validation json.
type BidsResultStruct struct {
	Issues struct {
		Errors []struct {
			Key      string `json:"key"`
			Severity string `json:"severity"`
			Reason   string `json:"reason"`
			Files    []struct {
				Key  string `json:"key"`
				Code int    `json:"code"`
				File struct {
					string       `json:"name"`
					Path         string `json:"path"`
					RelativePath string `json:"relativePath"`
				} `json:"file"`
				Evidence  interface{} `json:"evidence"`
				Line      interface{} `json:"line"`
				Character interface{} `json:"character"`
				Severity  string      `json:"severity"`
				Reason    string      `json:"reason"`
			} `json:"files"`
			AdditionalFileCount int `json:"additionalFileCount"`
			Code                int `json:"code"`
		} `json:"errors"`
		Warnings []struct {
			Key      string `json:"key"`
			Severity string `json:"severity"`
			Reason   string `json:"reason"`
			Files    []struct {
				Key  string `json:"key"`
				Code int    `json:"code"`
				File struct {
					Name         string `json:"name"`
					Path         string `json:"path"`
					RelativePath string `json:"relativePath"`
					Stats        struct {
						Dev         int       `json:"dev"`
						Mode        int       `json:"mode"`
						Nlink       int       `json:"nlink"`
						UID         int       `json:"uid"`
						Gid         int       `json:"gid"`
						Rdev        int       `json:"rdev"`
						Blksize     int       `json:"blksize"`
						Ino         int       `json:"ino"`
						Size        int       `json:"size"`
						Blocks      int       `json:"blocks"`
						AtimeMs     float64   `json:"atimeMs"`
						MtimeMs     float64   `json:"mtimeMs"`
						CtimeMs     float64   `json:"ctimeMs"`
						BirthtimeMs float64   `json:"birthtimeMs"`
						Atime       time.Time `json:"atime"`
						Mtime       time.Time `json:"mtime"`
						Ctime       time.Time `json:"ctime"`
						Birthtime   time.Time `json:"birthtime"`
					} `json:"stats"`
				} `json:"file"`
				Evidence  interface{} `json:"evidence"`
				Line      interface{} `json:"line"`
				Character interface{} `json:"character"`
				Severity  string      `json:"severity"`
				Reason    string      `json:"reason"`
			} `json:"files"`
			AdditionalFileCount int `json:"additionalFileCount"`
			Code                int `json:"code"`
		} `json:"warnings"`
		Ignored []interface{} `json:"ignored"`
	} `json:"issues"`
	Summary struct {
		Sessions   []interface{} `json:"sessions"`
		Subjects   []string      `json:"subjects"`
		Tasks      []string      `json:"tasks"`
		Modalities []string      `json:"modalities"`
		TotalFiles int           `json:"totalFiles"`
		Size       int           `json:"size"`
	} `json:"summary"`
}

// Results returns the results of a previously run validation.
func Results(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	user := vars["user"]
	repo := vars["repo"]
	validator := strings.ToLower(vars["validator"])
	if !helpers.SupportedValidator(validator) {
		log.ShowWrite("[Error] unsupported validator '%s'\n", validator)
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("404 Nothing to see here...")))
		return
	}
	log.ShowWrite("[Info] '%s' results for repo '%s/%s'\n", validator, user, repo)

	srvcfg := config.Read()
	resID, ok := vars["id"]
	if !ok {
		resHistory := resultsHistory(validator, user, repo)
		if len(resHistory.Results) < 1 {
			log.ShowWrite("[Info] Results ID not specified: Rendering the default one")
			resID = srvcfg.Label.ResultsFolder
		} else {
			log.ShowWrite("[Info] Results ID not specified: Rendering the last one")
			resID = resHistory.Results[0].Alt
		}
	}
	resdir := filepath.Join(srvcfg.Dir.Result, validator, user, repo, resID)

	fp := filepath.Join(resdir, srvcfg.Label.ResultsBadge)
	badge, err := ioutil.ReadFile(fp)
	if err != nil {
		log.ShowWrite("[Error] serving '%s/%s' badge: %s\n", user, repo, err.Error())
	}

	fp = filepath.Join(resdir, srvcfg.Label.ResultsFile)
	content, err := ioutil.ReadFile(fp)
	if err != nil {
		notValidatedYet(w, r, badge, strings.ToUpper(validator), user, repo)
		return
	}

	if string(content) == progressmsg {
		// validation in progress
		renderInProgress(w, r, badge, validator, user, repo)
		return
	}

	switch validator {
	case "bids":
		renderBIDSResults(w, r, badge, content, user, repo)
	case "nix":
		renderNIXResults(w, r, badge, content, user, repo)
	case "odml":
		renderODMLResults(w, r, badge, content, user, repo)
	default:
		log.ShowWrite("[Error] Validator %q is supported but no render result function is set up", validator)
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("404 Validator results missing")))
	}
	return
}

func notValidatedYet(w http.ResponseWriter, r *http.Request, badge []byte, validator, user, repo string) {
	tmpl := template.New("layout")
	tmpl, err := tmpl.Parse(templates.Layout)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}
	tmpl, err = tmpl.Parse(templates.NotValidatedYet)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}

	// Parse results into html template and serve it
	head := fmt.Sprintf("%s validation for %s/%s", validator, user, repo)
	loggedUsername := getLoggedUserName(r)
	srvcfg := config.Read()
	year, _, _ := time.Now().Date()
	info := struct {
		Badge       template.HTML
		Header      string
		Content     string
		GinURL      string
		CurrentYear int
		HrefURL1    string
		HrefAlt1    string
		HrefText1   string
		HrefURL2    string
		HrefAlt2    string
		HrefText2   string
		UserName    string
	}{template.HTML(badge), head, string(notvalidatedyet), srvcfg.GINAddresses.WebURL, year,
		"/pubvalidate", "Validate now", "Validate this repository right now",
		filepath.Join("/repos", user, repo, "hooks"), "Go Back", "Go back to repository information page",
		loggedUsername,
	}

	err = tmpl.ExecuteTemplate(w, "layout", info)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}
}

func renderInProgress(w http.ResponseWriter, r *http.Request, badge []byte, validator, user, repo string) {
	tmpl := template.New("layout")
	tmpl, err := tmpl.Parse(templates.Layout)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}
	tmpl, err = tmpl.Parse(templates.GenericResults)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}

	// Parse results into html template and serve it
	head := fmt.Sprintf("%s validation for %s/%s", strings.ToUpper(validator), user, repo)
	srvcfg := config.Read()
	resHistory := resultsHistory(validator, user, repo)
	loggedUsername := getLoggedUserName(r)
	year, _, _ := time.Now().Date()
	svgload, err := ioutil.ReadFile("/assets/svgload.svg")
	if err != nil {
		svgload = []byte("<svg></svg>")
	}
	info := struct {
		Badge       template.HTML
		Header      string
		Content     string
		GinURL      string
		CurrentYear int
		UserName    string
		*ResultsHistoryStruct
		LoadingSVG template.HTML
	}{template.HTML(badge), head, string(progressmsg), srvcfg.GINAddresses.WebURL, year, loggedUsername, &resHistory, template.HTML(svgload)}

	err = tmpl.ExecuteTemplate(w, "layout", info)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}
}

func myReadDir(dirname string) ([]os.FileInfo, error) {
	f, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	list, err := f.Readdir(-1)
	if err != nil {
		return nil, err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ModTime().Unix() > list[j].ModTime().Unix() })
	return list, nil
}

func resultsHistory(validator, user, repo string) ResultsHistoryStruct {
	var ret ResultsHistoryStruct
	srvcfg := config.Read()
	resdir := filepath.Join(srvcfg.Dir.Result, validator, user, repo)
	fileinfos, err := myReadDir(resdir)
	if err != nil {
		log.ShowWrite("[Error] cannot retrieve results history '%s/%s' result: %s\n", user, repo, err.Error())
		return ret
	}
	for _, i := range fileinfos {
		pth := filepath.Join("/results", strings.Split(resdir, "results/")[1], i.Name())
		fp := filepath.Join(resdir, i.Name(), srvcfg.Label.ResultsBadge)
		badge, err := ioutil.ReadFile(fp)
		if err != nil {
			badge = []byte("<svg></svg>")
		}
		if i.IsDir() && i.Name() != "." {
			var res Result
			res.Href = pth
			res.Alt = i.Name()
			res.Text1 = i.ModTime().Format("2006-01-02")
			res.Text2 = i.ModTime().Format("15:04:05")
			res.Badge = template.HTML(badge)
			ret.Results = append(ret.Results, res)
		}
	}
	return ret
}

func renderBIDSResults(w http.ResponseWriter, r *http.Request, badge []byte, content []byte, user, repo string) {
	// Parse results file
	var resBIDS BidsResultStruct
	err := json.Unmarshal(content, &resBIDS)
	errMsg := ""
	if err != nil {
		log.ShowWrite("[Error] unmarshalling '%s/%s' result: %s\n", user, repo, err.Error())
		errMsg = "Could not validate format as BIDS."
	}

	// Parse html template
	tmpl := template.New("layout")
	tmpl, err = tmpl.Parse(templates.Layout)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}
	tmpl, err = tmpl.Parse(templates.BidsResults)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}

	// Parse results into html template and serve it
	head := fmt.Sprintf("BIDS validation for %s/%s", user, repo)
	year, _, _ := time.Now().Date()
	srvcfg := config.Read()
	resHistory := resultsHistory("bids", user, repo)
	loggedUsername := getLoggedUserName(r)
	info := struct {
		Badge  template.HTML
		Header string
		*BidsResultStruct
		GinURL      string
		CurrentYear int
		UserName    string
		*ResultsHistoryStruct
		ErrorMessage string
	}{template.HTML(badge), head, &resBIDS, srvcfg.GINAddresses.WebURL, year, loggedUsername, &resHistory, errMsg}

	err = tmpl.ExecuteTemplate(w, "layout", info)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}
}

func renderNIXResults(w http.ResponseWriter, r *http.Request, badge []byte, content []byte, user, repo string) {
	// Parse results file
	// Parse html template
	tmpl := template.New("layout")
	tmpl, err := tmpl.Parse(templates.Layout)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}
	tmpl, err = tmpl.Parse(templates.GenericResults)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}

	// Parse results into html template and serve it
	head := fmt.Sprintf("NIX validation for %s/%s", user, repo)
	resHistory := resultsHistory("nix", user, repo)
	year, _, _ := time.Now().Date()
	svgload := []byte("")
	loggedUsername := getLoggedUserName(r)
	srvcfg := config.Read()
	info := struct {
		Badge       template.HTML
		Header      string
		Content     string
		GinURL      string
		CurrentYear int
		UserName    string
		*ResultsHistoryStruct
		LoadingSVG template.HTML
	}{template.HTML(badge), head, string(content), srvcfg.GINAddresses.WebURL, year, loggedUsername, &resHistory, template.HTML(svgload)}

	err = tmpl.ExecuteTemplate(w, "layout", info)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}
}

func renderODMLResults(w http.ResponseWriter, r *http.Request, badge []byte, content []byte, user, repo string) {
	// Parse results file
	// Parse html template
	tmpl := template.New("layout")
	tmpl, err := tmpl.Parse(templates.Layout)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}
	tmpl, err = tmpl.Parse(templates.GenericResults)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}

	// Parse results into html template and serve it
	head := fmt.Sprintf("odML validation for %s/%s", user, repo)
	resHistory := resultsHistory("odml", user, repo)
	loggedUsername := getLoggedUserName(r)
	svgload := []byte("")
	srvcfg := config.Read()
	year, _, _ := time.Now().Date()
	info := struct {
		Badge       template.HTML
		Header      string
		Content     string
		GinURL      string
		CurrentYear int
		UserName    string
		*ResultsHistoryStruct
		LoadingSVG template.HTML
	}{template.HTML(badge), head, string(content), srvcfg.GINAddresses.WebURL, year, loggedUsername, &resHistory, template.HTML(svgload)}

	err = tmpl.ExecuteTemplate(w, "layout", info)
	if err != nil {
		log.ShowWrite("[Error] '%s/%s' result: %s\n", user, repo, err.Error())
		http.ServeContent(w, r, "unavailable", time.Now(), bytes.NewReader([]byte("500 Something went wrong...")))
		return
	}
}
