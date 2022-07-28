package web

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	gingit "github.com/G-Node/gin-cli/git"
	"github.com/G-Node/gin-valid/internal/log"
	humanize "github.com/dustin/go-humanize"
)

// All types are copies of the private gin-client
// types required to run git and annex commands
// via the gin client.

type localAnnexAction struct {
	Command string   `json:"command"`
	Note    string   `json:"note"`
	Success bool     `json:"success"`
	Key     string   `json:"key"`
	File    string   `json:"file"`
	Errors  []string `json:"error-messages"`
}

type localAnnexProgress struct {
	Action          localAnnexAction `json:"action"`
	ByteProgress    int              `json:"byte-progress"`
	TotalSize       int              `json:"total-size"`
	PercentProgress string           `json:"percent-progress"`
}

// localCalcRate is a copy of the private gin-client function
// calcRate required to run the gin-client annex get.
func localCalcRate(dbytes int, dt time.Duration) string {
	dtns := dt.Nanoseconds()
	if dtns <= 0 || dbytes <= 0 {
		return ""
	}
	rate := int64(dbytes) * 1000000000 / dtns
	return fmt.Sprintf("%s/s", humanize.IBytes(uint64(rate)))
}

// remoteAnnexGet retrieves the annex content of all annex files at a provided
// git directory path. Function returns if the directory path is not found.
// The "rawMode" argument defines whether the annex command output will be
// raw or json formatted.
// The status channel 'getchan' is closed when this function returns.
// This function is a modified version of the gin-client annex get function to
// support execution in a specified git directory without the need to change
// directory.
func remoteAnnexGet(gitdir string, getchan chan<- gingit.RepoFileStatus, rawMode bool) {
	defer close(getchan)
	log.ShowWrite("[Info] remoteAnnexGet at directory %q", gitdir)
	if _, err := os.Stat(gitdir); os.IsNotExist(err) {
		log.ShowWrite("[Warning] directory %q not found", gitdir)
		return
	}

	cmdargs := []string{"git", "-C", gitdir, "annex", "get", "."}
	if !rawMode {
		cmdargs = append(cmdargs, "--json-progress")
	}
	cmd := gingit.AnnexCommand("version")
	cmd.Args = cmdargs
	log.ShowWrite("[Info] remoteAnnexGet: %v", cmdargs)
	if err := cmd.Start(); err != nil {
		getchan <- gingit.RepoFileStatus{Err: err}
		return
	}

	var status gingit.RepoFileStatus
	status.State = "Downloading"

	var outline []byte
	var rerr error
	var progress localAnnexProgress
	var getresult localAnnexAction
	var prevByteProgress int
	var prevT time.Time

	for rerr = nil; rerr == nil; outline, rerr = cmd.OutReader.ReadBytes('\n') {
		if len(outline) == 0 {
			// skip empty lines
			continue
		}

		if rawMode {
			lineInput := cmd.Args
			input := strings.Join(lineInput, " ")
			status.RawInput = input
			status.RawOutput = string(outline)
			getchan <- status
			continue
		}

		err := json.Unmarshal(outline, &progress)
		if err != nil || progress.Action.Command == "" {
			// File done? Check if succeeded and continue to next line
			err = json.Unmarshal(outline, &getresult)
			if err != nil || getresult.Command == "" {
				// Couldn't parse output
				log.ShowWrite("[Warning] Could not parse 'git annex get' output")
				log.ShowWrite(string(outline))
				// TODO: Print error at the end: Command succeeded but there was an error understanding the output
				continue
			}
			status.FileName = getresult.File
			if getresult.Success {
				status.Progress = "100%"
				status.Err = nil
			} else {
				errmsg := getresult.Note
				if strings.Contains(errmsg, "Unable to access") {
					errmsg = "authorisation failed or remote storage unavailable"
				}
				status.Err = fmt.Errorf("failed: %s", errmsg)
			}
		} else {
			status.FileName = progress.Action.File
			status.Progress = progress.PercentProgress
			dbytes := progress.ByteProgress - prevByteProgress
			now := time.Now()
			dt := now.Sub(prevT)
			status.Rate = localCalcRate(dbytes, dt)
			prevByteProgress = progress.ByteProgress
			prevT = now
			status.Err = nil
		}

		getchan <- status
	}
	if cmd.Wait() != nil {
		var stderr, errline []byte
		for rerr = nil; rerr == nil; errline, rerr = cmd.OutReader.ReadBytes('\000') {
			stderr = append(stderr, errline...)
		}
		log.ShowWrite("[Error] remoteAnnexGet: %s", string(stderr))
	}
}

// remoteCommitCheckout remotely checks out a provided git commit at
// a provided directory location. It is assumed, that the
// directory location is the root of the required git repository.
// The function does not check whether the directory exists or
// if it is a git repository.
func remoteCommitCheckout(gitdir, hash string) error {
	log.ShowWrite("[Info] checking out commit %q at %q", hash, gitdir)
	cmdargs := []string{"git", "-C", gitdir, "checkout", hash, "--"}
	cmd := gingit.Command("version")
	cmd.Args = cmdargs
	_, stderr, err := cmd.OutputError()
	if err != nil {
		log.ShowWrite("[Error] %s; %s", err.Error(), string(stderr))
		return fmt.Errorf(string(stderr))
	}
	return nil
}
