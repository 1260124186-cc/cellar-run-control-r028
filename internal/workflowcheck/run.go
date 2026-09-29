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
	dataDir, err := os.MkdirTemp("", "cellar-run-check-*")
	if err != nil {
		return fmt.Errorf("create check directory: %w", err)
	}
	defer os.RemoveAll(dataDir)

	if name != "formula-approval" && name != "vessel-run-lifecycle" &&
		name != "observations-completion" && name != "token-lifecycle" {
		return fmt.Errorf("unknown workflow check %q", name)
	}

	// The token lifecycle check owns its own server restarts.
	if name == "token-lifecycle" {
		return tokenLifecycle(dataDir)
	}

	server, err := startCheckServer(dataDir)
	if err != nil {
		return err
	}
	defer server.Close()
	api := newClient(server.URL)
	if err := api.registerCaller("workflow-check"); err != nil {
		return err
	}

	switch name {
	case "formula-approval":
		if err := formulaApproval(api); err != nil {
			return err
		}
	case "vessel-run-lifecycle":
		if err := vesselRunLifecycle(api); err != nil {
			return err
		}
	case "observations-completion":
		if err := observationsCompletion(api); err != nil {
			return err
		}
	}
	fmt.Printf("workflow check passed: %s\n", name)
	return nil
}

// startCheckServer opens the snapshot directory fresh and serves the real
// handler, which also simulates a process restart when called repeatedly on
// the same directory.
func startCheckServer(dataDir string) (*httptest.Server, error) {
	store, err := storage.Open(dataDir)
	if err != nil {
		return nil, err
	}
	app := service.New(store, clock.System{}, 0)
	return httptest.NewServer(httpapi.NewHandler(app)), nil
}
