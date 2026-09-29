package httpapi

import (
	"net/http"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/service"
)

func NewHandler(app *service.Service) http.Handler {
	// Business mux holds every route that requires an authenticated caller.
	business := http.NewServeMux()
	registerFormulaRoutes(business, app)
	registerVesselRoutes(business, app)
	registerRunRoutes(business, app)
	registerAuthenticatedCallerRoutes(business, app)
	guarded := withAuthentication(app, business)

	mux := http.NewServeMux()
	// Enrollment is special: it is unauthenticated only for the one-time
	// bootstrap and enforces authentication itself afterwards.
	registerEnrollmentRoute(mux, app)
	// The subtree match delegates every remaining /v1 route to the guard.
	mux.Handle("/v1/", guarded)
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]any{
			"status":   "ok",
			"revision": app.Revision(),
		})
	})
	return withRecovery(mux)
}

func withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				writeJSON(response, http.StatusInternalServerError, errorResponse{
					Error: errorBody{
						Code:   "internal_failure",
						Detail: "request could not be completed",
					},
				})
			}
		}()
		next.ServeHTTP(response, request)
	})
}
