package web

import (
	"fmt"

	gingit "github.com/G-Node/gin-cli/git"
	"github.com/G-Node/gin-valid/internal/log"
)

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
