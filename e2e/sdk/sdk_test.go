package sdk_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/pkg/emulator"
)

func TestOfficialManagementSDKs(t *testing.T) {
	if os.Getenv("APIM_RUN_EXTERNAL_SDK_TESTS") != "1" {
		t.Skip("set APIM_RUN_EXTERNAL_SDK_TESTS=1 to run external SDK witnesses")
	}
	emu := emulator.StartT(t, emulator.WithTLS())
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("sdk-backend"))
	}))
	defer backend.Close()
	certificatePath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certificatePath, emu.CACertificate, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	environment := append(os.Environ(),
		"APIM_ENDPOINT="+emu.ManagementEndpoint,
		"APIM_SUBSCRIPTION_ID="+emu.SubscriptionID,
		"APIM_RESOURCE_GROUP="+emu.ResourceGroup,
		"APIM_SERVICE_NAME="+emu.ServiceName,
		"APIM_BACKEND_URL="+backend.URL,
		"NODE_EXTRA_CA_CERTS="+certificatePath,
		"REQUESTS_CA_BUNDLE="+certificatePath,
		"SSL_CERT_FILE="+certificatePath,
	)
	tests := []struct {
		name    string
		command string
		args    []string
		dir     string
	}{
		{"javascript", "pnpm", []string{"test"}, filepath.Join(root, "e2e", "javascript")},
		{"python", venvPython(root), []string{"witness.py"}, filepath.Join(root, "e2e", "python")},
		{"dotnet", "dotnet", []string{"run", "--project", "Witness.csproj"}, filepath.Join(root, "e2e", "dotnet")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(test.command, test.args...)
			command.Dir = test.dir
			command.Env = environment
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %v\n%s", command.Args, err, output)
			}
			t.Logf("%s", output)
		})
	}
}

// venvPython locates the interpreter inside the witness virtualenv. Windows
// puts it in Scripts\python.exe; every other platform in bin/python. Hard-coding
// the POSIX path made this suite unrunnable on Windows even though every other
// witness works there.
func venvPython(root string) string {
	venv := filepath.Join(root, "e2e", "python", ".venv")
	if runtime.GOOS == "windows" {
		return filepath.Join(venv, "Scripts", "python.exe")
	}
	return filepath.Join(venv, "bin", "python")
}
