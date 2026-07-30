package emulator

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	"github.com/calvinchengx/azure-apim-emulator/internal/config"
	"github.com/calvinchengx/azure-apim-emulator/internal/server"
)

func TestStartAndClose(t *testing.T) {
	backend := &http.Client{}
	emu, err := Start(WithService("custom", "westus"), WithStrictPolicies(), WithBackendClient(backend))
	if err != nil {
		t.Fatal(err)
	}
	dataDir := emu.DataDir
	if emu.Origin != emu.ManagementEndpoint || emu.Origin != emu.GatewayEndpoint ||
		emu.ServiceName != "custom" || !strings.HasSuffix(emu.ServiceID(), "/service/custom") {
		t.Fatalf("fixture = %+v", emu)
	}
	response, err := emu.HTTPClient().Get(emu.Origin + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health = %d", response.StatusCode)
	}
	emu.Close()
	emu.Close()
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("data directory remains: %v", err)
	}
}

func TestStartTLSAndOptions(t *testing.T) {
	emu := StartT(t, WithTLS(), WithEntra("https://issuer.test/tenant/v2.0", "https://issuer.test/keys", http.DefaultClient))
	if !strings.HasPrefix(emu.Origin, "https://") || len(emu.CACertificate) == 0 {
		t.Fatalf("origin = %q", emu.Origin)
	}
	response, err := emu.HTTPClient().Get(emu.Origin + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
}

func TestStartFailures(t *testing.T) {
	oldTemp, oldRemove, oldServer := makeTempDir, removeAll, newServer
	t.Cleanup(func() {
		makeTempDir = oldTemp
		removeAll = oldRemove
		newServer = oldServer
	})
	want := errors.New("failed")
	makeTempDir = func(string, string) (string, error) { return "", want }
	if _, err := Start(); !errors.Is(err, want) {
		t.Fatalf("temp error = %v", err)
	}
	makeTempDir = oldTemp

	removed := ""
	removeAll = func(path string) error { removed = path; return nil }
	if _, err := Start(WithService("", "local")); err == nil || removed == "" {
		t.Fatalf("config error = %v, removed = %q", err, removed)
	}
	removeAll = oldRemove

	newServer = func(*config.Config, auth.RequestValidator, *http.Client, *http.Client) (*server.Server, error) {
		return nil, want
	}
	if _, err := Start(); !errors.Is(err, want) {
		t.Fatalf("server error = %v", err)
	}
}

type fakeTB struct {
	fatal    bool
	cleanups []func()
}

func (f *fakeTB) Helper()               {}
func (f *fakeTB) Cleanup(fn func())     { f.cleanups = append(f.cleanups, fn) }
func (f *fakeTB) Fatalf(string, ...any) { f.fatal = true; panic("fatal") }

func TestStartTContract(t *testing.T) {
	fake := &fakeTB{}
	emu := StartT(fake)
	if fake.fatal || len(fake.cleanups) != 1 {
		t.Fatalf("fatal=%v cleanups=%d", fake.fatal, len(fake.cleanups))
	}
	fake.cleanups[0]()
	_ = emu

	oldTemp := makeTempDir
	t.Cleanup(func() { makeTempDir = oldTemp })
	makeTempDir = func(string, string) (string, error) { return "", errors.New("failed") }
	failing := &fakeTB{}
	defer func() {
		_ = recover()
		if !failing.fatal {
			t.Fatal("StartT did not fail the test")
		}
	}()
	StartT(failing)
	t.Fatal("StartT returned after Fatalf")
}
