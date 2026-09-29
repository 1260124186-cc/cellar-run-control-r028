package workflowcheck

import (
	"fmt"
	"net/http/httptest"
	"os"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/clock"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/httpapi"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/service"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/storage"
)

func Run(name string) error {
	switch name {
	case "local-token-auth":
		return localTokenAuth()
	case "formula-approval", "vessel-run-lifecycle", "observations-completion":
		return runBusinessCheck(name)
	default:
		return fmt.Errorf("unknown workflow check %q", name)
	}
}

func runBusinessCheck(name string) error {
	dataDir, err := os.MkdirTemp("", "cellar-run-check-*")
	if err != nil {
		return fmt.Errorf("create check directory: %w", err)
	}
	defer os.RemoveAll(dataDir)

	server, err := startServer(dataDir, clock.System{})
	if err != nil {
		return err
	}
	defer server.Close()

	api := newClient(server.URL)
	if err := bootstrapCheckCaller(api, "workflow-check"); err != nil {
		return err
	}

	switch name {
	case "formula-approval":
		err = formulaApproval(api)
	case "vessel-run-lifecycle":
		err = vesselRunLifecycle(api)
	case "observations-completion":
		err = observationsCompletion(api)
	}
	if err != nil {
		return err
	}
	fmt.Printf("workflow check passed: %s\n", name)
	return nil
}

func startServer(dataDir string, timeSource clock.Clock) (*httptest.Server, error) {
	store, err := storage.Open(dataDir)
	if err != nil {
		return nil, err
	}
	app := service.New(store, timeSource)
	return httptest.NewServer(httpapi.NewHandler(app)), nil
}

func bootstrapCheckCaller(api *client, name string) error {
	response, err := api.call("POST", "/v1/callers", map[string]any{
		"name": name,
	}, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(response, 201, "bootstrap check caller"); err != nil {
		return err
	}
	var enrollment enrollmentView
	if err := response.decode(&enrollment); err != nil {
		return err
	}
	if enrollment.Token == "" || enrollment.Caller.ID == "" {
		return errInvalidWorkflow("bootstrap enrollment did not return a token or caller id")
	}
	api.setToken(enrollment.Token)
	return nil
}
