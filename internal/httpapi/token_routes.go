package httpapi

import (
	"net/http"
	"time"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/service"
)

type registerTokenRequest struct {
	Caller     string `json:"caller"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

// tokenView never exposes the stored secret hash.
type tokenView struct {
	ID        string             `json:"token_id"`
	Caller    string             `json:"caller"`
	State     domain.TokenStatus `json:"state"`
	IssuedAt  time.Time          `json:"issued_at"`
	ExpiresAt time.Time          `json:"expires_at"`
	RevokedAt *time.Time         `json:"revoked_at,omitempty"`
}

// issuedTokenView includes the plaintext presented token exactly once.
type issuedTokenView struct {
	tokenView
	Token string `json:"token"`
}

func registerTokenRoutes(mux *http.ServeMux, app *service.Service) {
	mux.HandleFunc("POST /v1/tokens", func(response http.ResponseWriter, request *http.Request) {
		body, err := decodeJSON[registerTokenRequest](response, request)
		if !handleDecode(response, err) {
			return
		}
		issued, err := app.RegisterToken(service.RegisterTokenInput{
			Caller:     body.Caller,
			TTLSeconds: body.TTLSeconds,
		})
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, issuedTokenView{
			tokenView: toTokenView(app, issued.Record),
			Token:     issued.Token,
		})
	})

	mux.HandleFunc("GET /v1/tokens", func(response http.ResponseWriter, _ *http.Request) {
		tokens, err := app.ListTokens()
		if err != nil {
			writeDomainError(response, err)
			return
		}
		views := make([]tokenView, 0, len(tokens))
		for _, record := range tokens {
			views = append(views, toTokenView(app, record))
		}
		writeJSON(response, http.StatusOK, map[string]any{"tokens": views})
	})

	mux.HandleFunc("POST /v1/tokens/verify", func(response http.ResponseWriter, request *http.Request) {
		presented, err := bearerToken(request)
		if err != nil {
			writeDomainError(response, err)
			return
		}
		record, err := app.Authenticate(presented)
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, toTokenView(app, record))
	})

	mux.HandleFunc("POST /v1/tokens/{id}/revoke", func(response http.ResponseWriter, request *http.Request) {
		record, err := app.RevokeToken(request.PathValue("id"))
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, toTokenView(app, record))
	})
}

func toTokenView(app *service.Service, record domain.AuthToken) tokenView {
	return tokenView{
		ID:        record.ID,
		Caller:    record.Caller,
		State:     app.TokenState(record),
		IssuedAt:  record.IssuedAt,
		ExpiresAt: record.ExpiresAt,
		RevokedAt: record.RevokedAt,
	}
}
