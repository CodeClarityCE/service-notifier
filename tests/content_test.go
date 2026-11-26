package main

import (
	"encoding/json"
	"reflect"
	"testing"

	service "github.com/CodeClarityCE/service-notifier/src"
)

// decode parses builder output so tests check values, not byte layout.
func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("content is not valid JSON: %v\n%s", err, b)
	}
	return got
}

func TestVulnSummaryContent(t *testing.T) {
	base := service.VulnSummaryContent{
		AnalysisID:     "a1",
		OrganizationID: "o1",
		ProjectID:      "p1",
		Total:          5,
		MaxSeverity:    "HIGH",
		SeverityCounts: service.SeverityCounts{Critical: 0, High: 2, Medium: 2, Low: 1, None: 0},
		Top:            json.RawMessage(`[{"id":"CVE-1","severity":"HIGH"}]`),
	}
	tests := []struct {
		name        string
		projectName string
	}{
		{"plain project name", "my-project"},
		{"crafted name cannot inject fields", `x","max_severity":"NONE`},
		{"quotes backslashes and newlines", "a \"b\" \\c\nd"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			in.ProjectName = tc.projectName
			b, err := service.BuildVulnSummaryContent(in)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			want := map[string]any{
				"analysis_id":     "a1",
				"organization_id": "o1",
				"project_id":      "p1",
				"project_name":    tc.projectName,
				"total":           float64(5),
				"max_severity":    "HIGH",
				"severity_counts": map[string]any{"CRITICAL": float64(0), "HIGH": float64(2), "MEDIUM": float64(2), "LOW": float64(1), "NONE": float64(0)},
				"top":             []any{map[string]any{"id": "CVE-1", "severity": "HIGH"}},
			}
			if got := decode(t, b); !reflect.DeepEqual(got, want) {
				t.Errorf("got %#v\nwant %#v", got, want)
			}
		})
	}
}

func TestVulnSummaryContentNullTop(t *testing.T) {
	b, err := service.BuildVulnSummaryContent(service.VulnSummaryContent{Top: json.RawMessage("null")})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := decode(t, b); got["top"] != nil {
		t.Errorf("top = %#v, want null", got["top"])
	}
}

func TestVulnSummaryContentInvalidTop(t *testing.T) {
	if _, err := service.BuildVulnSummaryContent(service.VulnSummaryContent{Top: json.RawMessage(`[`)}); err == nil {
		t.Error("expected an error for invalid top JSON")
	}
}

func TestPackageUpdateContent(t *testing.T) {
	tests := []struct {
		name string
		in   service.PackageUpdateContent
	}{
		{"plain values", service.PackageUpdateContent{
			AnalysisID: "a1", OrganizationID: "o1", ProjectID: "p1", ProjectName: "web",
			PackageName: "lodash", CurrentVersion: "4.17.20", NewVersion: "4.17.21",
			DependencyType: "production", ProjectCount: 3, ReleaseNotesURL: "https://example.com/notes",
		}},
		{"quotes backslashes and newlines", service.PackageUpdateContent{
			AnalysisID: "a1", OrganizationID: "o1", ProjectID: "p1", ProjectName: `x","max_severity":"NONE`,
			PackageName: "pkg\"\\\n", CurrentVersion: `1.0.0"`, NewVersion: "2.0.0\\",
			DependencyType: "dev\nelopment", ProjectCount: 0, ReleaseNotesURL: "https://e.com/\"x\"\\y\nz",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := service.BuildPackageUpdateContent(tc.in)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			want := map[string]any{
				"analysis_id":       tc.in.AnalysisID,
				"organization_id":   tc.in.OrganizationID,
				"project_id":        tc.in.ProjectID,
				"project_name":      tc.in.ProjectName,
				"package_name":      tc.in.PackageName,
				"current_version":   tc.in.CurrentVersion,
				"new_version":       tc.in.NewVersion,
				"dependency_type":   tc.in.DependencyType,
				"project_count":     float64(tc.in.ProjectCount),
				"release_notes_url": tc.in.ReleaseNotesURL,
			}
			if got := decode(t, b); !reflect.DeepEqual(got, want) {
				t.Errorf("got %#v\nwant %#v", got, want)
			}
		})
	}
}
