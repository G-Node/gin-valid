package config

import (
	"os"
	"path/filepath"
)

// Executables used by the server.
type Executables struct {
	BIDS string `json:"bids"`
	NIX  string `json:"nix"`
	ODML string `json:"odml"`
}

// Directories used by the server for temporary and long term storage.
type Directories struct {
	Temp   string `json:"temp"`
	Result string `json:"result"`
	Log    string `json:"log"`
	Tokens string `json:"tokens"`
}

// Denotations provide any frequently used file names or other denotations
// e.g. validation result files, badge or result folder names.
type Denotations struct {
	LogFile              string `json:"logfile"`
	ResultsFolder        string `json:"resultsfolder"`
	ResultsFile          string `json:"resultsfile"`
	ResultsBadge         string `json:"resultsbadge"`
	ValidationConfigFile string `json:"valcfgfile"`
}

// GINAddresses specify http and ssh access to the companion GIN service.
type GINAddresses struct {
	WebURL string `json:"weburl"`
	GitURL string `json:"giturl"`
}

// Settings provide the default server settings.
type Settings struct {
	RootURL     string   `json:"rooturl"`
	Port        string   `json:"port"`
	LogSize     int      `json:"logsize"`
	GINUser     string   `json:"ginuser"`
	GINPassword string   `json:"ginpassword"`
	ClientID    string   `json:"clientid"`
	HookSecret  string   `json:"hooksecret"`
	CookieName  string   `json:"cookiename"`
	Validators  []string `json:"validators"`
}

// ServerCfg holds the config used to setup the gin validation server and
// the paths to all required executables, temporary and permanent folders.
type ServerCfg struct {
	Settings     Settings     `json:"settings"`
	Exec         Executables  `json:"executables"`
	Dir          Directories  `json:"directories"`
	Label        Denotations  `json:"denotations"`
	GINAddresses GINAddresses `json:"ginaddresses"`
}

var defaultCfg = ServerCfg{
	Settings{
		Port:        "3033",
		LogSize:     1048576,
		GINUser:     "ServiceWaiter",
		GINPassword: "",
		ClientID:    "gin-valid",
		HookSecret:  "",
		CookieName:  "gin-valid-session",
		Validators:  []string{"bids", "nix", "odml"},
	},
	Executables{
		BIDS: "bids-validator",
		NIX:  "nixio",
		ODML: "odml-validate",
	},
	Directories{
		Temp:   filepath.Join(os.Getenv("GINVALIDHOME"), "tmp"),
		Log:    filepath.Join(os.Getenv("GINVALIDHOME"), "log"),
		Result: filepath.Join(os.Getenv("GINVALIDHOME"), "results"),
		Tokens: filepath.Join(os.Getenv("GINVALIDHOME"), "tokens"),
	},
	Denotations{
		LogFile:              "ginvalid.log",
		ResultsFolder:        "latest",
		ResultsFile:          "results.json",
		ResultsBadge:         "results.svg",
		ValidationConfigFile: "ginvalidation.yaml",
	},
	GINAddresses{
		WebURL: "https://gin.g-node.org:443",
		GitURL: "git@gin.g-node.org:22",
	},
}

// Read returns the default server configuration.
func Read() ServerCfg {
	return defaultCfg
}

// Set sets the server configuration.
func Set(cfg ServerCfg) {
	defaultCfg = cfg
}
