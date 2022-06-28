package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"github.com/G-Node/gin-cli/ginclient"
	cliconfig "github.com/G-Node/gin-cli/ginclient/config"
	"github.com/G-Node/gin-cli/git"
	"github.com/G-Node/gin-valid/internal/config"
	"github.com/G-Node/gin-valid/internal/helpers"
	"github.com/G-Node/gin-valid/internal/log"
	"github.com/G-Node/gin-valid/internal/web"
	"github.com/docopt/docopt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

const usage = `Server validating BIDS files

Usage:
  ginvalid [--listen=<port>] [--config=<path>]
  ginvalid -h | --help
  ginvalid --version

Options:
  -h --help           Show this screen.
  --version           Print version.
  --listen=<port>     Port to listen at [default:3033]
  --config=<path>     Path to a json server config file
  `

func registerRoutes(r *mux.Router) {
	r.StrictSlash(true)
	r.HandleFunc("/", web.Root)
	r.HandleFunc("/pubvalidate", web.PubValidateGet).Methods("GET")
	r.HandleFunc("/pubvalidate", web.PubValidatePost).Methods("POST")
	r.HandleFunc("/validate/{validator}/{user}/{repo}", web.Validate).Methods("POST")
	r.HandleFunc("/status/{validator}/{user}/{repo}", web.Status).Methods("GET")
	r.HandleFunc("/results/{validator}/{user}/{repo}", web.Results).Methods("GET")
	r.HandleFunc("/results/{validator}/{user}/{repo}/{id}", web.Results).Methods("GET")
	r.HandleFunc("/login", web.LoginGet).Methods("GET")
	r.HandleFunc("/login", web.LoginPost).Methods("POST")
	r.HandleFunc("/logout", web.Logout).Methods("GET")
	r.HandleFunc("/repos", web.ListRepos).Methods("GET")
	r.HandleFunc("/repos/{user}", web.ListRepos).Methods("GET")
	r.HandleFunc("/repos/{user}/{repo}/{validator}/enable", web.EnableHook).Methods("GET")
	r.HandleFunc("/repos/{user}/{repo}/{hookid}/disable", web.DisableHook).Methods("GET")
	r.HandleFunc("/repos/{user}/{repo}/hooks", web.ShowRepo).Methods("GET")
	r.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", http.FileServer(http.Dir("/assets"))))
}

func startupCheck(srvcfg config.ServerCfg) {
	// Check whether the required directories are available and accessible
	if !helpers.ValidDirectory(srvcfg.Dir.Temp) {
		os.Exit(-1)
	}

	log.ShowWrite("[Warmup] using temp directory: '%s'", srvcfg.Dir.Temp)
	log.ShowWrite("[Warmup] using results directory '%s'", srvcfg.Dir.Result)

	// Check bids-validator is installed
	outstr, err := helpers.AppVersionCheck(srvcfg.Exec.BIDS)
	if err != nil {
		log.ShowWrite("[Error] checking bids-validator '%s'", err.Error())
		os.Exit(-1)
	}
	log.ShowWrite("[Warmup] using bids-validator v%s", strings.TrimSpace(outstr))

	commcheck(srvcfg)
}

func commcheck(srvcfg config.ServerCfg) {
	clicfg := cliconfig.ServerCfg{}
	webcfg, err := cliconfig.ParseWebString(srvcfg.GINAddresses.WebURL)
	if err != nil {
		log.ShowWrite("[Error] Web URL for GIN server %q could not be parsed: %s", srvcfg.GINAddresses.WebURL, err.Error())
		os.Exit(-1)
	}
	gitcfg, err := cliconfig.ParseGitString(srvcfg.GINAddresses.GitURL)
	if err != nil {
		log.ShowWrite("[Error] Git URL for GIN server %q could not be parsed: %s", srvcfg.GINAddresses.GitURL, err.Error())
		os.Exit(-1)
	}
	clicfg.Web = webcfg
	clicfg.Git = gitcfg
	hostkeystr, fingerprint, err := git.GetHostKey(gitcfg)
	if err != nil {
		log.ShowWrite("[Error] Failed to get host key for Git server %q: %s", gitcfg.AddressStr(), err.Error())
		os.Exit(-1)
	}
	log.ShowWrite("[Warmup] Host key fingerprint for %q: %s", gitcfg.AddressStr(), fingerprint)
	clicfg.Git.HostKey = hostkeystr
	cliconfig.AddServerConf("gin", clicfg)
	git.WriteKnownHosts()
	if err != nil {
		log.ShowWrite("[Error] Failed to write known hosts file: %s", err.Error())
		os.Exit(-1)
	}
	cli := ginclient.New("gin")
	err = cli.Login(srvcfg.Settings.GINUser, srvcfg.Settings.GINPassword, srvcfg.Settings.ClientID)
	if err != nil {
		log.ShowWrite("Failed to login to GIN server: %s", err.Error())
		os.Exit(-1)
	}
	log.ShowWrite("[Warmup] GIN server configuration OK")
}

func main() {

	// Initialize and read the default server config
	srvcfg := config.Read()

	// Parse commandline arguments
	args, err := docopt.ParseArgs(usage, nil, "v1.0.2")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[Error] parsing cli arguments: '%s', abort...\n\n", err.Error())
		os.Exit(-1)
	}

	// Parse and load custom server confguration
	if args["--config"] != nil {
		content, err := ioutil.ReadFile(args["--config"].(string))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Error] reading config file %v\n", args["--config"])
			os.Exit(-1)
		}

		// Overwrite any default settings with information from the
		// provided config file.
		err = json.Unmarshal(content, &srvcfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Error] unmarshalling config file %s\n", err.Error())
			os.Exit(-1)
		}
		config.Set(srvcfg)
	}

	// TODO: Create missing directories defined in cfg

	err = log.Init()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Error] opening logfile '%s'\n", err.Error())
		os.Exit(-1)
	}
	defer log.Close()

	startupCheck(srvcfg)

	// Log cli arguments
	log.Write("[Warmup] cli arguments: %v\n", args)

	// Use port if provided.
	var port string
	if argport := args["--listen"]; argport != nil {
		port = argport.(string)
	}

	if !helpers.IsValidPort(port) {
		log.ShowWrite("[Warning] could not parse a valid port number, using default")
		port = srvcfg.Settings.Port
	}
	port = fmt.Sprintf(":%s", port)
	log.ShowWrite("[Warmup] using port: '%s'", port)

	log.ShowWrite("[Warmup] registering routes")
	router := mux.NewRouter()
	registerRoutes(router)

	handler := handlers.CORS(
		handlers.AllowedHeaders([]string{"Accept", "Content-Type", "Authorization"}),
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET"}),
	)(router)

	server := http.Server{
		Addr:    port,
		Handler: handler,
	}

	// Monitor the environment for shutdown signals to
	// gracefully shutdown the server.
	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt)
		<-sigchan
		log.ShowWrite("[Info] System interrupt, shutting down server")
		err := server.Shutdown(context.Background())
		if err != nil {
			log.ShowWrite("[Error] on server shutdown: %v", err)
		}
	}()

	log.ShowWrite("[Start] Listen and serve")
	err = server.ListenAndServe()
	if err == http.ErrServerClosed {
		log.Close()
		os.Exit(0)
	} else if err != nil {
		log.ShowWrite("[Error] Server startup: '%v', abort...\n\n", err)
		log.Close()
		os.Exit(-1)
	}
}
