package workflowcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type client struct {
	baseURL string
	token   string
	http    *http.Client
}

type response struct {
	status int
	body   []byte
}

func newClient(baseURL string) *client {
	return &client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (c *client) call(
	method string,
	path string,
	payload any,
	expectedVersion *int64,
) (response, error) {
	return c.callWithToken(method, path, payload, expectedVersion, c.token)
}

// callWithToken issues a request with an explicit bearer token; pass an
// empty token to send no Authorization header at all.
func (c *client) callWithToken(
	method string,
	path string,
	payload any,
	expectedVersion *int64,
	token string,
) (response, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return response{}, fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return response{}, fmt.Errorf("create request: %w", err)
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if expectedVersion != nil {
		request.Header.Set("X-Expected-Version", fmt.Sprintf("%d", *expectedVersion))
	}
	raw, err := c.http.Do(request)
	if err != nil {
		return response{}, fmt.Errorf("perform request: %w", err)
	}
	defer raw.Body.Close()
	content, err := io.ReadAll(io.LimitReader(raw.Body, 2<<20))
	if err != nil {
		return response{}, fmt.Errorf("read response: %w", err)
	}
	return response{status: raw.StatusCode, body: content}, nil
}

// callWithRawAuthorization issues a request with an exact Authorization
// header value, used to verify malformed-scheme handling.
func (c *client) callWithRawAuthorization(method, path, authorization string) (response, error) {
	request, err := http.NewRequest(method, c.baseURL+path, nil)
	if err != nil {
		return response{}, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Authorization", authorization)
	raw, err := c.http.Do(request)
	if err != nil {
		return response{}, fmt.Errorf("perform request: %w", err)
	}
	defer raw.Body.Close()
	content, err := io.ReadAll(io.LimitReader(raw.Body, 2<<20))
	if err != nil {
		return response{}, fmt.Errorf("read response: %w", err)
	}
	return response{status: raw.StatusCode, body: content}, nil
}

// registerCaller issues a fresh token and stores it so subsequent calls are
// authenticated.
func (c *client) registerCaller(name string) error {
	registered, err := c.call("POST", "/v1/tokens", map[string]any{"caller": name}, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(registered, http.StatusCreated, "register workflow caller"); err != nil {
		return err
	}
	var issued issuedTokenView
	if err := registered.decode(&issued); err != nil {
		return err
	}
	if issued.Token == "" {
		return fmt.Errorf("register workflow caller: response did not include a token")
	}
	c.token = issued.Token
	return nil
}

func (r response) decode(target any) error {
	if err := json.Unmarshal(r.body, target); err != nil {
		return fmt.Errorf("decode response %q: %w", string(r.body), err)
	}
	return nil
}

func (r response) errorCode() string {
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(r.body, &body); err != nil {
		return ""
	}
	return body.Error.Code
}

func requireStatus(actual response, expected int, operation string) error {
	if actual.status != expected {
		return fmt.Errorf("%s: expected status %d, got %d: %s",
			operation, expected, actual.status, strings.TrimSpace(string(actual.body)))
	}
	return nil
}

func requireCode(actual response, expectedStatus int, expectedCode, operation string) error {
	if err := requireStatus(actual, expectedStatus, operation); err != nil {
		return err
	}
	if actual.errorCode() != expectedCode {
		return fmt.Errorf("%s: expected error %q, got %q",
			operation, expectedCode, actual.errorCode())
	}
	return nil
}
