package web

import (
	"testing"
)

func TestTokenLinkToSessionWrong(t *testing.T) {
	err := linkToSession("wtf", "wtf")
	if err == nil {
		t.Fatal("expected error on linkToSession(username string, sessionid string)")
	}
}

func TestTokenGetTokenBySessionWrong(t *testing.T) {
	_, err := getTokenBySession("wtf")
	if err == nil {
		t.Fatal("expected error on getTokenBySession(sessionid string)")
	}
}

func TestTokenRmTokenRepoLinkWrong(t *testing.T) {
	err := rmTokenRepoLink("wtf")
	if err == nil {
		t.Fatal("expected error on rmTokenRepoLink(repopath string)")
	}
}

func TestTokenGetTokenByUsernameWrong(t *testing.T) {
	_, err := getTokenByUsername("wtf")
	if err == nil {
		t.Fatal("expected error on getTokenByUsername(username string)")
	}
}
