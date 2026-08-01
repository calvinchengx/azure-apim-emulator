package differential_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/pkg/emulator"
)

type fixtureStep struct {
	Method         string `json:"method"`
	Path           string `json:"path"`
	BodyFile       string `json:"bodyFile"`
	ExpectBodyFile string `json:"expectBodyFile"`
	ExpectStatus   int    `json:"expectStatus"`
}

type fixtureScenario struct {
	ID         string        `json:"id"`
	APIVersion string        `json:"apiVersion"`
	Steps      []fixtureStep `json:"steps"`
}

func TestLocalDifferentialFixtures(t *testing.T) {
	manifest := loadFixtureManifest(t)
	for _, entry := range manifest.Scenarios {
		if entry.AzureRequired {
			continue
		}
		t.Run(entry.ID, func(t *testing.T) {
			scenario := loadScenario(t, entry.Fixture)
			if scenario.ID != entry.ID || scenario.APIVersion != entry.APIVersion {
				t.Fatalf("scenario metadata mismatch: %+v", scenario)
			}
			runScenario(t, scenario)
		})
	}
}

func loadFixtureManifest(t *testing.T) fixtureManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "fixture-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest fixtureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func loadScenario(t *testing.T, name string) fixtureScenario {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "scenarios", name))
	if err != nil {
		t.Fatal(err)
	}
	var scenario fixtureScenario
	if err := json.Unmarshal(data, &scenario); err != nil {
		t.Fatal(err)
	}
	return scenario
}

func runScenario(t *testing.T, scenario fixtureScenario) {
	t.Helper()
	emu := emulator.StartT(t)
	for index, step := range scenario.Steps {
		var body io.Reader
		if step.BodyFile != "" {
			data, err := os.ReadFile(filepath.Join("testdata", step.BodyFile))
			if err != nil {
				t.Fatal(err)
			}
			body = bytes.NewReader(data)
		}
		path := emu.ServiceID()
		if step.Path != "service" {
			path += "/" + strings.TrimPrefix(step.Path, "/")
		}
		request, err := http.NewRequest(step.Method, emu.ManagementEndpoint+path+"?api-version="+scenario.APIVersion, body)
		if err != nil {
			t.Fatal(err)
		}
		if step.BodyFile != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := emu.HTTPClient().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		responseBody, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.StatusCode != step.ExpectStatus {
			t.Fatalf("step %d %s %s = %d, want %d: %s", index, step.Method, step.Path, response.StatusCode, step.ExpectStatus, responseBody)
		}
		if len(responseBody) == 0 {
			t.Fatalf("step %d returned an empty response", index)
		}
		var document map[string]any
		if err := json.Unmarshal(responseBody, &document); err != nil {
			t.Fatalf("step %d response is not JSON: %v", index, err)
		}
		if step.ExpectBodyFile != "" {
			goldenData, err := os.ReadFile(filepath.Join("testdata", step.ExpectBodyFile))
			if err != nil {
				t.Fatal(err)
			}
			var golden map[string]any
			if err := json.Unmarshal(goldenData, &golden); err != nil {
				t.Fatal(err)
			}
			if !fixtureSubset(normalizeFixture(golden, manifestRules()), normalizeFixture(document, manifestRules())) {
				t.Fatalf("step %d response does not contain golden projection\nwant: %s\ngot: %s", index, canonicalJSON(golden), canonicalJSON(document))
			}
		}
	}
}

func manifestRules() []string {
	return []string{"request-id", "correlation-id", "timestamps", "generated-secrets", "regional-hostnames", "unordered-collections"}
}

func fixtureSubset(expected, actual any) bool {
	switch typed := expected.(type) {
	case map[string]any:
		actualMap, ok := actual.(map[string]any)
		if !ok {
			return false
		}
		for key, value := range typed {
			actualValue, ok := actualMap[key]
			if !ok || !fixtureSubset(value, actualValue) {
				return false
			}
		}
		return true
	case []any:
		actualSlice, ok := actual.([]any)
		if !ok || len(typed) != len(actualSlice) {
			return false
		}
		for index := range typed {
			if !fixtureSubset(typed[index], actualSlice[index]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(expected, actual)
	}
}

func normalizeFixture(value any, rules []string) any {
	ruleSet := map[string]bool{}
	for _, rule := range rules {
		ruleSet[rule] = true
	}
	return normalizeFixtureValue(value, ruleSet, "")
}

func normalizeFixtureValue(value any, rules map[string]bool, key string) any {
	switch typed := value.(type) {
	case map[string]any:
		result := map[string]any{}
		keys := make([]string, 0, len(typed))
		for name := range typed {
			keys = append(keys, name)
		}
		sort.Strings(keys)
		for _, name := range keys {
			lower := strings.ToLower(name)
			if (rules["request-id"] || rules["correlation-id"]) && (strings.Contains(lower, "requestid") || strings.Contains(lower, "correlationid") || strings.Contains(lower, "correlation-id") || strings.Contains(lower, "request-id")) {
				continue
			}
			if rules["timestamps"] && (strings.HasSuffix(lower, "at") || strings.Contains(lower, "timestamp") || strings.Contains(lower, "duration")) {
				continue
			}
			result[name] = normalizeFixtureValue(typed[name], rules, name)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = normalizeFixtureValue(item, rules, key)
		}
		if rules["unordered-collections"] {
			sort.SliceStable(result, func(left, right int) bool {
				return canonicalJSON(result[left]) < canonicalJSON(result[right])
			})
		}
		return result
	case string:
		if rules["regional-hostnames"] && (strings.HasSuffix(strings.ToLower(typed), ".azure-api.net") || strings.HasSuffix(strings.ToLower(typed), ".management.azure-api.net")) {
			return "<regional-hostname>"
		}
		if rules["generated-secrets"] && (strings.Contains(strings.ToLower(key), "secret") || strings.Contains(strings.ToLower(key), "password")) {
			return "<generated-secret>"
		}
		return typed
	default:
		return value
	}
}

func canonicalJSON(value any) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func TestFixtureNormalization(t *testing.T) {
	input := map[string]any{
		"requestId":  "one",
		"createdAt":  "2026-08-01T00:00:00Z",
		"properties": map[string]any{"password": "secret", "gatewayUrl": "west.azure-api.net"},
		"items":      []any{"b", "a"},
	}
	got := normalizeFixture(input, []string{"request-id", "timestamps", "generated-secrets", "regional-hostnames", "unordered-collections"})
	want := map[string]any{
		"properties": map[string]any{"password": "<generated-secret>", "gatewayUrl": "<regional-hostname>"},
		"items":      []any{"a", "b"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized fixture = %s, want %s", fmt.Sprint(got), fmt.Sprint(want))
	}
	withTimestamps := normalizeFixture(input, manifestRules())
	if normalized, ok := withTimestamps.(map[string]any); !ok || normalized["createdAt"] != nil {
		t.Fatalf("timestamp was not normalized: %v", withTimestamps)
	}
}
