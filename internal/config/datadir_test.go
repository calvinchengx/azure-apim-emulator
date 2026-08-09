package config

import (
	"os"
	"testing"
)

// The unset/set-empty distinction IS the feature: leaving APIM_DATA_DIR alone
// persists to ./data, while setting it to the empty string opts back into
// in-memory. Three compose files depend on the second case, so a refactor that
// collapses the two would silently start writing SQLite files into throwaway
// container layers.
func TestDataDirDefaulting(t *testing.T) {
	t.Setenv("APIM_ENTRA_ISSUER", "https://localhost:8443/t/v2.0")

	t.Run("unset persists to the default dir", func(t *testing.T) {
		t.Setenv("APIM_DATA_DIR", "") // ensure t.Setenv restores whatever was there
		if err := os.Unsetenv("APIM_DATA_DIR"); err != nil {
			t.Fatal(err)
		}
		if got := FromEnvPartial().DataDir; got != DefaultDataDir {
			t.Fatalf("DataDir = %q, want %q", got, DefaultDataDir)
		}
	})

	t.Run("explicitly empty stays in-memory", func(t *testing.T) {
		t.Setenv("APIM_DATA_DIR", "")
		if got := FromEnvPartial().DataDir; got != "" {
			t.Fatalf("DataDir = %q, want \"\" (in-memory)", got)
		}
	})

	t.Run("a path is honoured", func(t *testing.T) {
		t.Setenv("APIM_DATA_DIR", "/tmp/apim-state")
		if got := FromEnvPartial().DataDir; got != "/tmp/apim-state" {
			t.Fatalf("DataDir = %q", got)
		}
	})
}
