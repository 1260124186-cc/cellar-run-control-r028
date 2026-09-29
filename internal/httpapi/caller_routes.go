package httpapi

import (
	"net/http"
	"time"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/service"
)

type registerCallerRequest struct {
	Name       string `json:"name"`
	TTLSeconds *int64 `json:"ttl_seconds"`
}

type callerView struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	IssuedBy  string     `json:"issued_by,omitempty"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	RevokedBy string     `json:"revoked_by,omitempty"`
}

type enrollmentView struct {
	Caller    callerView `json:"caller"`
	Token     string     `json:"token"`
	ExpiresIn int64      `json:"expires_in_seconds"`
}

func viewCaller(caller domain.Caller) callerView {
	view := callerView{
		ID:        caller.ID,
		Name:      caller.Name,
		IssuedBy:  caller.IssuedBy,
		IssuedAt:  caller.IssuedAt,
		ExpiresAt: caller.ExpiresAt,
		RevokedBy: caller.RevokedBy,
	}
	if caller.RevokedAt != nil {
		revoked := *caller.RevokedAt
		view.RevokedAt = &revoked
	}
	return view
}

func registerEnrollmentRoute(mux *http.ServeMux, app *service.Service) {
	mux.HandleFunc("POST /v1/callers", func(response http.ResponseWriter, request *http.Request) {
		// Enrollment is unauthenticated only while no caller exists; the
		// one-time bootstrap is closed atomically inside the service by the
		// same store mutation that records the first caller. Authentication
		// precedes body decoding so anonymous callers never reach validation.
		var issuerID *string
		if app.HasCallers() {
			rawToken, err := bearerToken(request)
			if err != nil {
				writeAuthError(response, err)
				return
			}
			issuer, err := app.Authenticate(rawToken)
			if err != nil {
				writeAuthError(response, err)
				return
			}
			issuerID = &issuer.ID
		}

		body, err := decodeJSON[registerCallerRequest](response, request)
		if !handleDecode(response, err) {
			return
		}

		enrollment, err := app.RegisterCaller(service.RegisterCallerInput{
			Name:       body.Name,
			TTLSeconds: body.TTLSeconds,
			IssuerID:   issuerID,
		})
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, enrollmentView{
			Caller:    viewCaller(enrollment.Caller),
			Token:     enrollment.RawToken,
			ExpiresIn: int64(enrollment.ExpiresAt.Sub(enrollment.Caller.IssuedAt).Seconds()),
		})
	})
}

func registerAuthenticatedCallerRoutes(mux *http.ServeMux, app *service.Service) {
	mux.HandleFunc("GET /v1/callers", func(response http.ResponseWriter, request *http.Request) {
		callers, err := app.ListCallers()
		if err != nil {
			writeDomainError(response, err)
			return
		}
		views := make([]callerView, 0, len(callers))
		for _, caller := range callers {
			views = append(views, viewCaller(caller))
		}
		writeJSON(response, http.StatusOK, map[string]any{"callers": views})
	})

	mux.HandleFunc("GET /v1/callers/me", func(response http.ResponseWriter, request *http.Request) {
		caller, ok := CallerFromContext(request.Context())
		if !ok {
			writeAuthError(response, domain.NewError(domain.CodeAuthMissing,
				"an authenticated caller is required"))
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"caller": viewCaller(caller)})
	})

	mux.HandleFunc("GET /v1/callers/{id}", func(response http.ResponseWriter, request *http.Request) {
		caller, err := app.GetCaller(request.PathValue("id"))
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"caller": viewCaller(caller)})
	})

	mux.HandleFunc("POST /v1/callers/{id}/revoke", func(response http.ResponseWriter, request *http.Request) {
		issuer, ok := CallerFromContext(request.Context())
		if !ok {
			writeAuthError(response, domain.NewError(domain.CodeAuthMissing,
				"an authenticated caller is required"))
			return
		}
		caller, err := app.RevokeCaller(request.PathValue("id"), issuer.ID)
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"caller": viewCaller(caller)})
	})
}
