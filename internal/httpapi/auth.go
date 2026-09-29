package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/service"
)

type callerContextKey struct{}

// withAuthentication requires a valid bearer token on every business route.
// GET /healthz and the /v1/tokens administration routes stay reachable
// without one; POST /v1/tokens/verify performs its own token check. A
// request is authorized at the single point its token check reads the
// store, so a committed revocation rejects every request authenticated
// after it and never produces a torn decision for a concurrent request.
func withAuthentication(app *service.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !requiresAuthentication(request.URL.Path) {
			next.ServeHTTP(response, request)
			return
		}
		presented, err := bearerToken(request)
		if err != nil {
			writeDomainError(response, err)
			return
		}
		token, err := app.Authenticate(presented)
		if err != nil {
			writeDomainError(response, err)
			return
		}
		ctx := context.WithValue(request.Context(), callerContextKey{}, token)
		next.ServeHTTP(response, request.WithContext(ctx))
	})
}

func requiresAuthentication(path string) bool {
	if !strings.HasPrefix(path, "/v1/") {
		return false
	}
	if path == "/v1/tokens" || strings.HasPrefix(path, "/v1/tokens/") {
		return false
	}
	return true
}

func bearerToken(request *http.Request) (string, error) {
	header := request.Header.Get("Authorization")
	if header == "" {
		return "", domain.NewError(domain.CodeTokenMissing,
			"an Authorization bearer token is required")
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", domain.FieldError(domain.CodeTokenMalformed,
			"Authorization", "must use the Bearer scheme with a single token")
	}
	return parts[1], nil
}

// CallerFromContext returns the authenticated caller record attached to a
// business route request, letting any handler identify its caller.
func CallerFromContext(ctx context.Context) (domain.AuthToken, bool) {
	token, ok := ctx.Value(callerContextKey{}).(domain.AuthToken)
	return token, ok
}
