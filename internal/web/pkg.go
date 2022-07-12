/*
Package web is responsible for logging users in to the validator service,
listing the user's repositories and their validation status/results, enabling
and disabling hooks on the GIN server running the validation.
*/
package web

const (
	serveralias     = "gin"
	progressmsg     = "A validation job for this repository is currently in progress. Please do not leave this page. When it is done, it will refresh automatically. You can also refresh this page manually as many times as you wish"
	notvalidatedyet = "This repository has not been validated yet. To see the results, update the repository."
)
