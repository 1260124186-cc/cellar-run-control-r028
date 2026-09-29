package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/service"
)

type callerContextKey struct{}

// CallerFromContext returns the authenticated caller placed by the middleware.
func CallerFromContext(ctx context.Context) (domain.Caller, bool) {
	caller, ok := ctx.Value(callerContextKey{}).(domain.Caller)
	return caller, ok
}

// withAuthentication wraps every business route. Health remains unauthenticated
// because the wrapper only guards patterns mounted under /v1/.
func withAuthentication(app *service.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		rawToken, err := bearerToken(request)
		if err != nil {
			writeAuthError(response, err)
			return
		}
		caller, err := app.Authenticate(rawToken)
		if err != nil {
			writeAuthError(response, err)
			return
		}
		response.Header().Set("X-Caller-ID", caller.ID)
		ctx := context.WithValue(request.Context(), callerContextKey{}, caller)
		next.ServeHTTP(response, request.WithContext(ctx))
	})
}

// bearerToken extracts a strictly formatted Bearer token from the
// Authorization header, mapping every shape defect to a stable code.
func bearerToken(request *http.Request) (string, error) {
	header := strings.TrimSpace(request.Header.Get("Authorization"))
	if header == "" {
		return "", domain.NewError(domain.CodeAuthMissing,
			"an Authorization bearer token is required")
	}
	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(strings.TrimSpace(scheme), "Bearer") {
		return "", domain.FieldError(domain.CodeAuthMalformed, "Authorization",
			`must use the "Bearer" scheme`)
	}
	value = strings.TrimSpace(value)
	if err := domain.ValidateToken(value, "Authorization"); err != nil {
		return "", err
	}
	return value, nil
}

func writeAuthError(response http.ResponseWriter, err error) {
	code := domain.CodeTokenUnknown
	detail := "the supplied credentials are not valid"
	var field string
	var domainErr *domain.Error
	if errors.As(err, &domainErr) {
		code = domainErr.Code
		detail = domainErr.Message
		field = domainErr.Field
	}
	response.Header().Set("WWW-Authenticate", `Bearer realm="cellar-run-control"`)
	writeJSON(response, http.StatusUnauthorized, errorResponse{
		Error: errorBody{Code: code, Detail: detail, Field: field},
	})
}
