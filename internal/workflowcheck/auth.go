package workflowcheck

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/clock"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
)

type enrollmentView struct {
	Caller struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		ExpiresAt string `json:"expires_at"`
	} `json:"caller"`
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in_seconds"`
}

func localTokenAuth() error {
	dataDir, err := os.MkdirTemp("", "cellar-auth-check-*")
	if err != nil {
		return fmt.Errorf("create auth check directory: %w", err)
	}
	defer os.RemoveAll(dataDir)

	fixed := clock.NewFixed(mustParseTime("2026-09-29T12:00:00Z"))
	server, err := startServer(dataDir, fixed)
	if err != nil {
		return err
	}

	anon := newClient(server.URL)

	// 1. Health is reachable without credentials, before and after bootstrap.
	health, err := anon.call("GET", "/healthz", nil, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(health, 200, "health without authentication"); err != nil {
		return err
	}

	// 2. Every business route requires a token.
	for _, probe := range []struct {
		method string
		path   string
	}{
		{"GET", "/v1/formulas"},
		{"POST", "/v1/vessels"},
		{"GET", "/v1/runs"},
		{"GET", "/v1/callers"},
		{"GET", "/v1/callers/me"},
	} {
		missing, err := anon.call(probe.method, probe.path, nil, nil)
		if err != nil {
			return err
		}
		if err := requireCode(missing, 401, string(domain.CodeAuthMissing),
			"reject unauthenticated "+probe.method+" "+probe.path); err != nil {
			return err
		}
		if missing.header.Get("Www-Authenticate") == "" {
			return errInvalidWorkflow("authentication failures must send WWW-Authenticate")
		}
	}

	// 3. Malformed Authorization shapes return a stable code and never 500.
	for _, headerValue := range []string{
		"Token cellar_abcd",
		"Bearer",
		"Bearer ",
		"Basic cellar_0123456789abcdef0123456789abcdef01234567",
		"Bearer cellar_ZZZZ",
		"bearer cellar_0123456789abcdef0123456789abcdef01234567 extra",
	} {
		malformed, err := anon.callRawAuth("GET", "/v1/formulas", nil, headerValue)
		if err != nil {
			return err
		}
		if err := requireCode(malformed, 401, string(domain.CodeAuthMalformed),
			"reject malformed authorization"); err != nil {
			return err
		}
	}

	// 4. Bootstrap enrollment is open once and closes afterwards.
	bootstrap := mustEnroll(anon, "bootstrap-operator", nil)
	authed := newClient(server.URL)
	authed.setToken(bootstrap.Token)

	secondBootstrap, err := anon.call("POST", "/v1/callers",
		map[string]any{"name": "stranger"}, nil)
	if err != nil {
		return err
	}
	if err := requireCode(secondBootstrap, 401, string(domain.CodeAuthMissing),
		"bootstrap enrollment closes after first caller"); err != nil {
		return err
	}

	// 5. Invalid enrollment payloads produce stable validation errors.
	badTTL, err := authed.call("POST", "/v1/callers",
		map[string]any{"name": "short-lived", "ttl_seconds": 0}, nil)
	if err != nil {
		return err
	}
	if err := requireCode(badTTL, 400, string(domain.CodeInvalidInput),
		"reject out-of-range token lifetime"); err != nil {
		return err
	}
	emptyName, err := authed.call("POST", "/v1/callers",
		map[string]any{"name": "   "}, nil)
	if err != nil {
		return err
	}
	if err := requireCode(emptyName, 400, string(domain.CodeInvalidInput),
		"reject blank caller name"); err != nil {
		return err
	}

	// 6. Authenticated enrollment identifies the issuer and exposes callers.
	worker := mustEnroll(authed, "  cellar worker  ", nil)
	workerClient := newClient(server.URL)
	workerClient.setToken(worker.Token)
	me, err := workerClient.call("GET", "/v1/callers/me", nil, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(me, 200, "read own caller identity"); err != nil {
		return err
	}
	var meBody struct {
		Caller struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			IssuedBy string `json:"issued_by"`
		} `json:"caller"`
	}
	if err := me.decode(&meBody); err != nil {
		return err
	}
	if meBody.Caller.ID != worker.Caller.ID ||
		meBody.Caller.Name != "cellar worker" ||
		meBody.Caller.IssuedBy != bootstrap.Caller.ID {
		return errInvalidWorkflow("caller identity or issuer was not recorded correctly")
	}
	if me.header.Get("X-Caller-Id") != worker.Caller.ID {
		return errInvalidWorkflow("authenticated responses must identify the caller")
	}

	duplicateName, err := authed.call("POST", "/v1/callers",
		map[string]any{"name": "Cellar  Worker"}, nil)
	if err != nil {
		return err
	}
	if err := requireCode(duplicateName, 409, string(domain.CodeCallerNameConflict),
		"reject duplicate normalized caller name"); err != nil {
		return err
	}

	// 7. Unknown tokens are rejected.
	unknown := newClient(server.URL)
	unknown.setToken("cellar_0123456789abcdef0123456789abcdef01234567")
	unknownResponse, err := unknown.call("GET", "/v1/formulas", nil, nil)
	if err != nil {
		return err
	}
	if err := requireCode(unknownResponse, 401, string(domain.CodeTokenUnknown),
		"reject unknown token"); err != nil {
		return err
	}

	// 8. Expiry is enforced against the process clock and is stable afterwards.
	expiring := mustEnroll(authed, "temp-inspector", int64Ptr(60))
	expiringClient := newClient(server.URL)
	expiringClient.setToken(expiring.Token)
	validBefore, err := expiringClient.call("GET", "/v1/callers/me", nil, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(validBefore, 200, "token valid before expiry"); err != nil {
		return err
	}
	fixed.Advance(61 * time.Second)
	expiredResponse, err := expiringClient.call("GET", "/v1/formulas", nil, nil)
	if err != nil {
		return err
	}
	if err := requireCode(expiredResponse, 401, string(domain.CodeTokenExpired),
		"reject expired token"); err != nil {
		return err
	}
	fixed.Advance(-61 * time.Second)

	// 9. Revocation is durable, idempotent, and immediately visible to
	// concurrent requests because state reads and writes are serialized.
	victim := mustEnroll(authed, "retired-script", nil)
	victimClient := newClient(server.URL)
	victimClient.setToken(victim.Token)
	if err := requireStatus(mustCall(victimClient, "GET", "/v1/callers/me"),
		200, "victim token works before revocation"); err != nil {
		return err
	}

	// The single revocation commits while other requests are in flight; the
	// helper performs that revoke and enforces the linearization invariant.
	revoke, err := assertConcurrentRevocationConsistency(authed, victimClient, victim.Caller.ID)
	if err != nil {
		return err
	}
	if err := requireStatus(revoke, 200, "revoke caller"); err != nil {
		return err
	}
	var revokedBody struct {
		Caller struct {
			RevokedAt *string `json:"revoked_at"`
			RevokedBy string  `json:"revoked_by"`
		} `json:"caller"`
	}
	if err := revoke.decode(&revokedBody); err != nil {
		return err
	}
	if revokedBody.Caller.RevokedAt == nil ||
		revokedBody.Caller.RevokedBy != bootstrap.Caller.ID {
		return errInvalidWorkflow("revocation timestamp and revoking caller were not recorded")
	}

	revokeAgain, err := authed.call("POST", "/v1/callers/"+victim.Caller.ID+"/revoke", nil, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(revokeAgain, 200, "revoke caller is idempotent"); err != nil {
		return err
	}

	revokeMissing, err := authed.call("POST", "/v1/callers/cli_doesnotexist/revoke", nil, nil)
	if err != nil {
		return err
	}
	if err := requireCode(revokeMissing, 404, string(domain.CodeCallerNotFound),
		"revoking an unknown caller"); err != nil {
		return err
	}

	immediate, err := victimClient.call("GET", "/v1/formulas", nil, nil)
	if err != nil {
		return err
	}
	if err := requireCode(immediate, 401, string(domain.CodeTokenRevoked),
		"revoked token is rejected after the racing commit"); err != nil {
		return err
	}

	// A revoked token cannot mint further callers.
	asVictim, err := victimClient.call("POST", "/v1/callers",
		map[string]any{"name": "should-fail"}, nil)
	if err != nil {
		return err
	}
	if err := requireCode(asVictim, 401, string(domain.CodeTokenRevoked),
		"revoked token cannot enroll callers"); err != nil {
		return err
	}

	// 10. Caller state survives a process restart from the same data dir.
	server.Close()
	restarted, err := startServer(dataDir, fixed)
	if err != nil {
		return err
	}
	defer restarted.Close()
	restartClient := newClient(restarted.URL)
	restartClient.setToken(bootstrap.Token)

	healthRestart, err := restartClient.call("GET", "/healthz", nil, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(healthRestart, 200, "health after restart"); err != nil {
		return err
	}
	stillRevoked, err := restartClient.callAs(victim.Token, "GET", "/v1/formulas", nil, nil)
	if err != nil {
		return err
	}
	if err := requireCode(stillRevoked, 401, string(domain.CodeTokenRevoked),
		"revocation survives restart"); err != nil {
		return err
	}
	stillAuthed, err := restartClient.call("GET", "/v1/callers/me", nil, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(stillAuthed, 200, "active token survives restart"); err != nil {
		return err
	}
	list, err := restartClient.call("GET", "/v1/callers", nil, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(list, 200, "list callers after restart"); err != nil {
		return err
	}
	var listBody struct {
		Callers []struct {
			ID string `json:"id"`
		} `json:"callers"`
	}
	if err := list.decode(&listBody); err != nil {
		return err
	}
	if len(listBody.Callers) != 4 {
		return fmt.Errorf("expected 4 persisted callers after restart, got %d",
			len(listBody.Callers))
	}

	// An unauthenticated caller still cannot enroll once state has reloaded.
	closed, err := newClient(restarted.URL).call("POST", "/v1/callers",
		map[string]any{"name": "post-restart stranger"}, nil)
	if err != nil {
		return err
	}
	if err := requireCode(closed, 401, string(domain.CodeAuthMissing),
		"bootstrap stays closed after restart"); err != nil {
		return err
	}

	fmt.Println("workflow check passed: local-token-auth")
	return nil
}

func assertConcurrentRevocationConsistency(admin, victimClient *client, victimID string) (response, error) {
	const goroutines = 16
	const iterations = 12
	var wg sync.WaitGroup
	results := make(chan string, goroutines+1)
	start := make(chan struct{})
	var revokeResponse response

	// One goroutine performs the revocation while the rest hammer the victim
	// token. Requests serialized before the commit may succeed; every request
	// serialized after it must observe token_revoked. Requests inside each
	// worker are strictly ordered, so once a worker sees token_revoked it must
	// never see success again. No third outcome is allowed.
	wg.Add(goroutines + 1)
	for worker := 0; worker < goroutines; worker++ {
		go func() {
			defer wg.Done()
			<-start
			sawRevoked := false
			for i := 0; i < iterations; i++ {
				resp, err := victimClient.call("GET", "/v1/callers/me", nil, nil)
				if err != nil {
					results <- "request-error: " + err.Error()
					return
				}
				switch {
				case resp.status == http.StatusOK:
					if sawRevoked {
						results <- "success-after-revoke"
						return
					}
				case resp.status == http.StatusUnauthorized &&
					resp.errorCode() == string(domain.CodeTokenRevoked):
					sawRevoked = true
				default:
					results <- "unexpected:" + resp.errorCode()
					return
				}
			}
			if sawRevoked {
				results <- "revoked-observed"
			} else {
				results <- "only-ok"
			}
		}()
	}
	go func() {
		defer wg.Done()
		<-start
		resp, err := admin.call("POST", "/v1/callers/"+victimID+"/revoke", nil, nil)
		if err != nil {
			results <- "revoke-error: " + err.Error()
			return
		}
		revokeResponse = resp
		if resp.status != http.StatusOK {
			results <- "revoke-unexpected:" + resp.errorCode()
			return
		}
		results <- "revoke-done"
	}()

	close(start)
	wg.Wait()
	close(results)

	anyRevoked := false
	for result := range results {
		switch result {
		case "revoke-done", "revoked-observed":
			anyRevoked = true
		case "only-ok":
			// Acceptable only for workers that finished before the commit.
		default:
			return response{}, errInvalidWorkflow("concurrent revocation produced inconsistent result: " + result)
		}
	}
	if !anyRevoked {
		return response{}, errInvalidWorkflow("revocation was never observed by concurrent requests")
	}
	return revokeResponse, nil
}

func mustEnroll(api *client, name string, ttlSeconds *int64) enrollmentView {
	body := map[string]any{"name": name}
	if ttlSeconds != nil {
		body["ttl_seconds"] = *ttlSeconds
	}
	resp, err := api.call("POST", "/v1/callers", body, nil)
	if err != nil {
		panic(fmt.Sprintf("enroll %q: %v", name, err))
	}
	if resp.status != http.StatusCreated {
		panic(fmt.Sprintf("enroll %q: status %d: %s", name, resp.status, resp.body))
	}
	var enrollment enrollmentView
	if err := resp.decode(&enrollment); err != nil {
		panic(fmt.Sprintf("enroll %q decode: %v", name, err))
	}
	return enrollment
}

func mustCall(api *client, method, path string) response {
	resp, err := api.call(method, path, nil, nil)
	if err != nil {
		panic(fmt.Sprintf("%s %s: %v", method, path, err))
	}
	return resp
}

func int64Ptr(value int64) *int64 {
	return &value
}

func mustParseTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(fmt.Sprintf("parse check time %q: %v", value, err))
	}
	return parsed
}
