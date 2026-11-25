package codeclarity

import "encoding/json"

// SeverityCounts holds the number of vulnerabilities per severity.
type SeverityCounts struct {
	Critical int `json:"CRITICAL"`
	High     int `json:"HIGH"`
	Medium   int `json:"MEDIUM"`
	Low      int `json:"LOW"`
	None     int `json:"NONE"`
}

// VulnSummaryContent is the stored content of a vulnerability summary notification.
type VulnSummaryContent struct {
	AnalysisID     string          `json:"analysis_id"`
	OrganizationID string          `json:"organization_id"`
	ProjectID      string          `json:"project_id"`
	ProjectName    string          `json:"project_name"`
	Total          int             `json:"total"`
	MaxSeverity    string          `json:"max_severity"`
	SeverityCounts SeverityCounts  `json:"severity_counts"`
	Top            json.RawMessage `json:"top"`
}

// PackageUpdateContent is the stored content of a package update notification.
type PackageUpdateContent struct {
	AnalysisID      string `json:"analysis_id"`
	OrganizationID  string `json:"organization_id"`
	ProjectID       string `json:"project_id"`
	ProjectName     string `json:"project_name"`
	PackageName     string `json:"package_name"`
	CurrentVersion  string `json:"current_version"`
	NewVersion      string `json:"new_version"`
	DependencyType  string `json:"dependency_type"`
	ProjectCount    int    `json:"project_count"`
	ReleaseNotesURL string `json:"release_notes_url"`
}

// BuildVulnSummaryContent encodes a vulnerability summary's content as JSON.
func BuildVulnSummaryContent(c VulnSummaryContent) ([]byte, error) {
	return json.Marshal(c)
}

// BuildPackageUpdateContent encodes a package update's content as JSON.
func BuildPackageUpdateContent(c PackageUpdateContent) ([]byte, error) {
	return json.Marshal(c)
}
