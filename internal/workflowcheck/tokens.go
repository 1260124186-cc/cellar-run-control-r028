package workflowcheck

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
)

// tokenLifecycle exercises registration, verification, stable
// authentication failures, revocation against concurrent requests,
// expiry, and persistence across a restart on the same data directory.
func tokenLifecycle(dataDir string) error {
	activeToken, revokedToken, expiredToken, err := tokenLifecycleBeforeRestart(dataDir)
	if err != nil {
		return err
	}

	server, err := startCheckServer(dataDir)
	if err != nil {
		return err
	}
	defer server.Close()
	api := newClient(server.URL)

	survived, err := api.callWithToken("GET", "/v1/formulas", nil, nil, activeToken)
	if err != nil {
		return err
	}
	if err := requireStatus(survived, 200, "active token after restart"); err != nil {
		return err
	}

	stillRevoked, err := api.callWithToken("GET", "/v1/formulas", nil, nil, revokedToken)
	if err != nil {
		return err
	}
	if err := requireCode(stillRevoked, 401, string(domain.CodeTokenRevoked),
		"revoked token after restart"); err != nil {
		return err
	}

	stillExpired, err := api.callWithToken("GET", "/v1/formulas", nil, nil, expiredToken)
	if err != nil {
		return err
	}
	if err := requireCode(stillExpired, 401, string(domain.CodeTokenExpired),
		"expired token after restart"); err != nil {
		return err
	}

	fmt.Println("workflow check passed: token-lifecycle")
	return nil
}

func tokenLifecycleBeforeRestart(dataDir string) (activeToken, revokedToken, expiredToken string, err error) {
	server, err := startCheckServer(dataDir)
	if err != nil {
		return "", "", "", err
	}
	defer server.Close()
	api := newClient(server.URL)

	health, err := api.call("GET", "/healthz", nil, nil)
	if err != nil {
		return "", "", "", err
	}
	if err := requireStatus(health, 200, "health check without token"); err != nil {
		return "", "", "", err
	}

	missing, err := api.call("GET", "/v1/formulas", nil, nil)
	if err != nil {
		return "", "", "", err
	}
	if err := requireCode(missing, 401, string(domain.CodeTokenMissing),
		"business route without token"); err != nil {
		return "", "", "", err
	}

	malformedScheme, err := api.callWithRawAuthorization("GET", "/v1/formulas", "Token abc")
	if err != nil {
		return "", "", "", err
	}
	if err := requireCode(malformedScheme, 401, string(domain.CodeTokenMalformed),
		"wrong authorization scheme"); err != nil {
		return "", "", "", err
	}

	malformed, err := api.callWithToken("GET", "/v1/formulas", nil, nil, "not-a-real-token")
	if err != nil {
		return "", "", "", err
	}
	if err := requireCode(malformed, 401, string(domain.CodeTokenMalformed),
		"malformed token"); err != nil {
		return "", "", "", err
	}

	unknown, err := api.callWithToken("GET", "/v1/formulas", nil, nil,
		"tok_0000000000000000000a."+strings.Repeat("0", 64))
	if err != nil {
		return "", "", "", err
	}
	if err := requireCode(unknown, 401, string(domain.CodeTokenInvalid),
		"unknown well-formed token"); err != nil {
		return "", "", "", err
	}

	registered, err := api.call("POST", "/v1/tokens",
		map[string]any{"caller": "Lifecycle Checker"}, nil)
	if err != nil {
		return "", "", "", err
	}
	if err := requireStatus(registered, 201, "register caller"); err != nil {
		return "", "", "", err
	}
	var issued issuedTokenView
	if err := registered.decode(&issued); err != nil {
		return "", "", "", err
	}
	if issued.Token == "" || issued.TokenID == "" || issued.State != string(domain.TokenActive) {
		return "", "", "", fmt.Errorf("register caller: unexpected response %s", registered.body)
	}

	listed, err := api.call("GET", "/v1/tokens", nil, nil)
	if err != nil {
		return "", "", "", err
	}
	if err := requireStatus(listed, 200, "list tokens without caller token"); err != nil {
		return "", "", "", err
	}
	if !strings.Contains(string(listed.body), "Lifecycle Checker") {
		return "", "", "", fmt.Errorf("token list does not include the registered caller")
	}
	if strings.Contains(string(listed.body), "secret_hash") {
		return "", "", "", fmt.Errorf("token list leaked a stored secret hash")
	}

	duplicate, err := api.call("POST", "/v1/tokens",
		map[string]any{"caller": "  lifecycle   checker "}, nil)
	if err != nil {
		return "", "", "", err
	}
	if err := requireCode(duplicate, 409, string(domain.CodeTokenCallerConflict),
		"duplicate caller registration"); err != nil {
		return "", "", "", err
	}

	verified, err := api.callWithToken("POST", "/v1/tokens/verify", nil, nil, issued.Token)
	if err != nil {
		return "", "", "", err
	}
	if err := requireStatus(verified, 200, "verify presented token"); err != nil {
		return "", "", "", err
	}
	var verifiedToken tokenView
	if err := verified.decode(&verifiedToken); err != nil {
		return "", "", "", err
	}
	if verifiedToken.Caller != "Lifecycle Checker" || verifiedToken.State != string(domain.TokenActive) {
		return "", "", "", fmt.Errorf("verify returned an unexpected caller")
	}

	verifiedMissing, err := api.call("POST", "/v1/tokens/verify", nil, nil)
	if err != nil {
		return "", "", "", err
	}
	if err := requireCode(verifiedMissing, 401, string(domain.CodeTokenMissing),
		"verify without token"); err != nil {
		return "", "", "", err
	}

	allowed, err := api.callWithToken("GET", "/v1/formulas", nil, nil, issued.Token)
	if err != nil {
		return "", "", "", err
	}
	if err := requireStatus(allowed, 200, "business route with valid token"); err != nil {
		return "", "", "", err
	}

	shortResponse, err := api.call("POST", "/v1/tokens",
		map[string]any{"caller": "Short Lived", "ttl_seconds": 1}, nil)
	if err != nil {
		return "", "", "", err
	}
	if err := requireStatus(shortResponse, 201, "register short-lived token"); err != nil {
		return "", "", "", err
	}
	var shortIssued issuedTokenView
	if err := shortResponse.decode(&shortIssued); err != nil {
		return "", "", "", err
	}
	time.Sleep(1100 * time.Millisecond)
	expiredUse, err := api.callWithToken("GET", "/v1/formulas", nil, nil, shortIssued.Token)
	if err != nil {
		return "", "", "", err
	}
	if err := requireCode(expiredUse, 401, string(domain.CodeTokenExpired),
		"use expired token"); err != nil {
		return "", "", "", err
	}
	expiredToken = shortIssued.Token

	if err := checkRevocationConcurrency(api, issued); err != nil {
		return "", "", "", err
	}

	revokedUse, err := api.callWithToken("GET", "/v1/formulas", nil, nil, issued.Token)
	if err != nil {
		return "", "", "", err
	}
	if err := requireCode(revokedUse, 401, string(domain.CodeTokenRevoked),
		"business route with revoked token"); err != nil {
		return "", "", "", err
	}
	revokedVerify, err := api.callWithToken("POST", "/v1/tokens/verify", nil, nil, issued.Token)
	if err != nil {
		return "", "", "", err
	}
	if err := requireCode(revokedVerify, 401, string(domain.CodeTokenRevoked),
		"verify revoked token"); err != nil {
		return "", "", "", err
	}
	revokedToken = issued.Token

	again, err := api.call("POST", "/v1/tokens/"+issued.TokenID+"/revoke", nil, nil)
	if err != nil {
		return "", "", "", err
	}
	if err := requireCode(again, 409, string(domain.CodeTokenState),
		"revoke token twice"); err != nil {
		return "", "", "", err
	}

	unknownRevoke, err := api.call("POST", "/v1/tokens/tok_0000000000000000000a/revoke", nil, nil)
	if err != nil {
		return "", "", "", err
	}
	if err := requireCode(unknownRevoke, 404, string(domain.CodeTokenNotFound),
		"revoke unknown token"); err != nil {
		return "", "", "", err
	}

	// Revocation released the caller name, so the same caller can register
	// again; this active token must survive the restart.
	reissued, err := api.call("POST", "/v1/tokens",
		map[string]any{"caller": "Lifecycle Checker"}, nil)
	if err != nil {
		return "", "", "", err
	}
	if err := requireStatus(reissued, 201, "re-register revoked caller"); err != nil {
		return "", "", "", err
	}
	var reissuedToken issuedTokenView
	if err := reissued.decode(&reissuedToken); err != nil {
		return "", "", "", err
	}
	return reissuedToken.Token, revokedToken, expiredToken, nil
}

// checkRevocationConcurrency revokes a token while several workers keep
// using it. Every observed result must be consistent with one ordering
// point: success before the revocation commits, token_revoked after it.
func checkRevocationConcurrency(api *client, issued issuedTokenView) error {
	const workers = 8
	var mu sync.Mutex
	var outcomes []string
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				result, err := api.callWithToken("GET", "/v1/formulas", nil, nil, issued.Token)
				outcome := "ok"
				if err != nil {
					outcome = "transport_error"
				} else if result.status != 200 {
					outcome = result.errorCode()
				}
				mu.Lock()
				outcomes = append(outcomes, outcome)
				mu.Unlock()
			}
		}()
	}
	revoked, err := api.call("POST", "/v1/tokens/"+issued.TokenID+"/revoke", nil, nil)
	close(stop)
	wg.Wait()
	if err != nil {
		return err
	}
	if err := requireStatus(revoked, 200, "revoke token during concurrent use"); err != nil {
		return err
	}
	for _, outcome := range outcomes {
		if outcome != "ok" && outcome != string(domain.CodeTokenRevoked) {
			return fmt.Errorf("request concurrent with revocation saw unexpected outcome %q", outcome)
		}
	}
	return nil
}
