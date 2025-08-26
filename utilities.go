package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	service "github.com/CodeClarityCE/service-notifier/src"
	"github.com/CodeClarityCE/utility-types/boilerplates"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

// handleNotification processes messages from the service_notifier queue using ServiceBase databases
func handleNotification(db *boilerplates.ServiceDatabases, d amqp.Delivery) {
	// First attempt specific message type detection directly
	var generic map[string]any
	if err := json.Unmarshal(d.Body, &generic); err == nil {
		if t, ok := generic["type"].(string); ok {
			switch t {
			case "vuln_summary":
				log.Printf("received vuln_summary message: %s", string(d.Body))
				handleVulnSummary(db, generic)
				return
			case "package_update":
				log.Printf("received package_update message: %s", string(d.Body))
				handlePackageUpdate(db, generic)
				return
			}
		}
	}

	// Fallback: legacy dispatcher message (package/version)
	var dispatcherMessage map[string]string
	if err := json.Unmarshal(d.Body, &dispatcherMessage); err != nil {
		log.Printf("unmarshal legacy message failed: %v", err)
		return
	}

	start := time.Now()
	// Legacy startAnalysis equivalent - for backward compatibility
	output := service.Start(db.CodeClarity, dispatcherMessage["package"], dispatcherMessage["version"], dispatcherMessage["key"])

	result := make(map[string]any)
	result["output"] = output

	log.Printf("legacy processing took %s, result: %v", time.Since(start), result)
}

func handleVulnSummary(db *boilerplates.ServiceDatabases, payload map[string]any) {
	log.Printf("handling vuln summary")
	orgIDStr, _ := payload["organization_id"].(string)
	analysisID, _ := payload["analysis_id"].(string)
	projectID, _ := payload["project_id"].(string)
	projectName, _ := payload["project_name"].(string) // Get project name if provided
	severityCountsAny, _ := payload["severity_counts"].(map[string]any)
	maxSeverity, _ := payload["max_severity"].(string)
	totalF, _ := payload["total"].(float64)
	total := int(totalF)

	// Default zero map if nil
	severityCounts := map[string]float64{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
	for k, v := range severityCountsAny {
		if f, ok := v.(float64); ok {
			severityCounts[k] = f
		}
	}

	nType := "info"
	switch maxSeverity {
	case "CRITICAL", "HIGH":
		nType = "error"
	case "MEDIUM":
		nType = "warning"
	}

	desc := "No vulnerabilities found"
	if total > 0 {
		critical := int(severityCounts["CRITICAL"])
		high := int(severityCounts["HIGH"])
		medium := int(severityCounts["MEDIUM"])
		low := int(severityCounts["LOW"])
		desc = fmt.Sprintf("%d vulnerabilities (Critical: %d, High: %d, Medium: %d, Low: %d). Max severity: %s.", total, critical, high, medium, low, maxSeverity)
		switch maxSeverity {
		case "CRITICAL", "HIGH":
			desc += " Immediate attention recommended."
		case "MEDIUM":
			desc += " Plan remediation soon."
		default:
			desc += " Monitor as needed."
		}
	}

	// Get top list as JSON string
	topBytes, _ := json.Marshal(payload["top"])

	ctx := context.Background()

	// 1) Collect users of organization from CODECLARITY DB (use bun placeholders '?')
	userIDs := make([]string, 0, 8)
	rowsK, err := db.CodeClarity.QueryContext(ctx, `SELECT m."userId" FROM organization_memberships m WHERE m."organizationId" = ?`, orgIDStr)
	if err != nil {
		log.Printf("user fetch (codeclarity) failed: %v", err)
		return
	}
	for rowsK.Next() {
		var uid string
		if err := rowsK.Scan(&uid); err != nil {
			log.Printf("scan user (codeclarity): %v", err)
			continue
		}
		userIDs = append(userIDs, uid)
	}
	rowsK.Close()
	if err := rowsK.Err(); err != nil {
		log.Printf("row err (codeclarity): %v", err)
	}
	if len(userIDs) == 0 {
		log.Printf("no users found for organization %s", orgIDStr)
	}

	// 2) Insert notification into CODECLARITY DB and attach users
	tx, err := db.CodeClarity.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		log.Printf("codeclarity tx begin failed: %v", err)
		return
	}
	defer tx.Rollback()

	var notifID uuid.UUID
	contentJSON := fmt.Sprintf(`{"analysis_id":"%s","organization_id":"%s","project_id":"%s","project_name":"%s","total":%d,"max_severity":"%s","severity_counts":%s,"top":%s}`,
		analysisID, orgIDStr, projectID, projectName, total, maxSeverity,
		toJSON(map[string]any{"CRITICAL": severityCounts["CRITICAL"], "HIGH": severityCounts["HIGH"], "MEDIUM": severityCounts["MEDIUM"], "LOW": severityCounts["LOW"], "NONE": severityCounts["NONE"]}), string(topBytes))
	err = tx.QueryRowContext(ctx, `INSERT INTO notification (title, description, content, type, content_type) VALUES (?,?,?::jsonb,?,?) RETURNING id`,
		"Vulnerability summary", desc, contentJSON, nType, "vuln_summary").Scan(&notifID)
	if err != nil {
		log.Printf("insert notif failed: %v", err)
		return
	}

	attached := 0
	for _, uid := range userIDs {
		if uid == "" {
			continue
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO notification_users_user ("notificationId", "userId") VALUES (?,?) ON CONFLICT DO NOTHING`, notifID, uid)
		if err != nil {
			log.Printf("attach user failed: %v", err)
			continue
		}
		attached++
	}
	if err := tx.Commit(); err != nil {
		log.Printf("commit err: %v", err)
		return
	}
	log.Printf("notification %s created; attached to %d users", notifID.String(), attached)
}

func handlePackageUpdate(db *boilerplates.ServiceDatabases, payload map[string]any) {
	log.Printf("handling package update")
	orgIDStr, _ := payload["organization_id"].(string)
	analysisID, _ := payload["analysis_id"].(string)
	projectID, _ := payload["project_id"].(string)
	projectName, _ := payload["project_name"].(string)
	packageName, _ := payload["package_name"].(string)
	currentVersion, _ := payload["current_version"].(string)
	newVersion, _ := payload["new_version"].(string)
	dependencyType, _ := payload["dependency_type"].(string)
	releaseNotesURL, _ := payload["release_notes_url"].(string)
	projectCount, _ := payload["project_count"].(float64)

	if orgIDStr == "" || packageName == "" || currentVersion == "" || newVersion == "" {
		log.Printf("incomplete package update payload")
		return
	}

	// Determine notification priority and styling based on dependency type
	var title, nType string
	var desc string

	if dependencyType == "production" {
		title = fmt.Sprintf("🔴 Production Update: %s", packageName)
		nType = "warning" // Higher priority for production dependencies
		desc = fmt.Sprintf("Production dependency %s can be updated from %s to %s", packageName, currentVersion, newVersion)
	} else if dependencyType == "development" {
		title = fmt.Sprintf("🟡 Dev Update: %s", packageName)
		nType = "info"
		desc = fmt.Sprintf("Development dependency %s can be updated from %s to %s", packageName, currentVersion, newVersion)
	} else {
		// Fallback for unknown dependency type
		title = fmt.Sprintf("Update available: %s", packageName)
		nType = "info"
		desc = fmt.Sprintf("%s can be updated from %s to %s", packageName, currentVersion, newVersion)
	}

	if projectName != "" {
		projectText := projectName
		if int(projectCount) > 1 {
			projectText = fmt.Sprintf("%d projects", int(projectCount))
		}

		if dependencyType == "production" {
			desc = fmt.Sprintf("Production dependency %s can be updated from %s to %s in %s", packageName, currentVersion, newVersion, projectText)
		} else if dependencyType == "development" {
			desc = fmt.Sprintf("Development dependency %s can be updated from %s to %s in %s", packageName, currentVersion, newVersion, projectText)
		} else {
			desc = fmt.Sprintf("%s can be updated from %s to %s in %s", packageName, currentVersion, newVersion, projectText)
		}
	}

	ctx := context.Background()

	// 1) Collect users of organization from CODECLARITY DB (use bun placeholders '?')
	userIDs := make([]string, 0, 8)
	rowsK, err := db.CodeClarity.QueryContext(ctx, `SELECT m."userId" FROM organization_memberships m WHERE m."organizationId" = ?`, orgIDStr)
	if err != nil {
		log.Printf("user fetch (codeclarity) failed: %v", err)
		return
	}
	for rowsK.Next() {
		var uid string
		if err := rowsK.Scan(&uid); err != nil {
			log.Printf("scan user (codeclarity): %v", err)
			continue
		}
		userIDs = append(userIDs, uid)
	}
	rowsK.Close()
	if err := rowsK.Err(); err != nil {
		log.Printf("row err (codeclarity): %v", err)
	}
	if len(userIDs) == 0 {
		log.Printf("no users found for organization %s", orgIDStr)
		return
	}

	// 2) Insert notification into CODECLARITY DB and attach users
	tx, err := db.CodeClarity.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		log.Printf("codeclarity tx begin failed: %v", err)
		return
	}
	defer tx.Rollback()

	var notifID uuid.UUID
	contentJSON := fmt.Sprintf(`{"analysis_id":"%s","organization_id":"%s","project_id":"%s","project_name":"%s","package_name":"%s","current_version":"%s","new_version":"%s","dependency_type":"%s","project_count":%d,"release_notes_url":"%s"}`,
		analysisID, orgIDStr, projectID, projectName, packageName, currentVersion, newVersion, dependencyType, int(projectCount), releaseNotesURL)
	err = tx.QueryRowContext(ctx, `INSERT INTO notification (title, description, content, type, content_type) VALUES (?,?,?::jsonb,?,?) RETURNING id`,
		title, desc, contentJSON, nType, "package_update").Scan(&notifID)
	if err != nil {
		log.Printf("insert notif failed: %v", err)
		return
	}

	attached := 0
	for _, uid := range userIDs {
		if uid == "" {
			continue
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO notification_users_user ("notificationId", "userId") VALUES (?,?) ON CONFLICT DO NOTHING`, notifID, uid)
		if err != nil {
			log.Printf("attach user failed: %v", err)
			continue
		}
		attached++
	}
	if err := tx.Commit(); err != nil {
		log.Printf("commit err: %v", err)
		return
	}
	log.Printf("package update notification %s created; attached to %d users", notifID.String(), attached)
}

func toJSON(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}
