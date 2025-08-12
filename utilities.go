package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	plugin "github.com/CodeClarityCE/utility-types/plugin_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// callback is a function that processes a message received from a plugin dispatcher.
// It takes the following parameters:
// - args: any, the arguments passed to the callback function.
// - config: types_plugin.Plugin, the configuration of the plugin.
// - message: []byte, the message received from the plugin dispatcher.
//
// The callback function performs the following steps:
// 1. Extracts the arguments from the args parameter.
// 2. Opens a database connection.
// 3. Reads the message and unmarshals it into a dispatcherMessage struct.
// 4. Starts a timer to measure the execution time.
// 5. Retrieves the analysis document from the database.
// 6. Starts the analysis using the startAnalysis function.
// 7. Prints the elapsed time.
// 8. Updates the analysis with the results and status.
// 9. Commits the transaction.
// 10. Sends the results to the plugins_dispatcher.
//
// If any error occurs during the execution of the callback function, it will be logged and the transaction will be aborted.
func callback(args any, config plugin.Plugin, message []byte) {
	// Get arguments
	s, ok := args.(Arguments)
	if !ok {
		log.Printf("not ok")
		return
	}

	// First attempt specific message type detection directly
	var generic map[string]any
	if err := json.Unmarshal(message, &generic); err == nil {
		if t, ok := generic["type"].(string); ok {
			switch t {
			case "vuln_summary":
				log.Printf("received vuln_summary message: %s", string(message))
				handleVulnSummary(s, generic)
				return
			case "package_update":
				log.Printf("received package_update message: %s", string(message))
				handlePackageUpdate(s, generic)
				return
			}
		}
	}

	// Fallback: legacy dispatcher message (package/version)
	var dispatcherMessage map[string]string
	if err := json.Unmarshal(message, &dispatcherMessage); err != nil {
		log.Printf("unmarshal legacy message failed: %v", err)
		return
	}

	start := time.Now()
	_, _, err := startAnalysis(s, dispatcherMessage, config)
	if err != nil {
		log.Printf("startAnalysis error: %v", err)
		return
	}
	log.Printf("legacy processing took %s", time.Since(start))
}

func handleVulnSummary(s Arguments, payload map[string]any) {
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
	rowsK, err := s.codeclarity.QueryContext(ctx, `SELECT m."userId" FROM organization_memberships m WHERE m."organizationId" = ?`, orgIDStr)
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
	tx, err := s.codeclarity.BeginTx(ctx, &sql.TxOptions{})
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

func handlePackageUpdate(s Arguments, payload map[string]any) {
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
	rowsK, err := s.codeclarity.QueryContext(ctx, `SELECT m."userId" FROM organization_memberships m WHERE m."organizationId" = ?`, orgIDStr)
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
	tx, err := s.codeclarity.BeginTx(ctx, &sql.TxOptions{})
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

// readConfig reads the configuration file and returns a Plugin object and an error.
// The configuration file is expected to be named "config.json" and should be located in the same directory as the source file.
// If the file cannot be opened or if there is an error decoding the file, an error is returned.
// The returned Plugin object contains the parsed configuration values, with the Key field set as the concatenation of the Name and Version fields.
// If there is an error registering the plugin, an error is returned.
func readConfig() (plugin.Plugin, error) {
	// Read config file
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Printf("%v", err)
		return plugin.Plugin{}, err
	}
	defer configFile.Close()

	// Decode config file
	var config plugin.Plugin
	jsonParser := json.NewDecoder(configFile)
	err = jsonParser.Decode(&config)
	if err != nil {
		log.Printf("%v", err)
		return plugin.Plugin{}, err
	}
	config.Name = config.Name + ":" + config.Version

	// err = register(config)
	// if err != nil {
	// 	log.Printf("%v", err)
	// 	return plugin.Plugin{}, err
	// }

	return config, nil
}

// register is a function that registers a plugin configuration in the database.
// It takes a config parameter of type types_plugin.Plugin, which represents the plugin configuration to be registered.
// The function returns an error if there was an issue with the registration process.
func register(config plugin.Plugin) error {
	host := os.Getenv("PG_DB_HOST")
	if host == "" {
		log.Printf("PG_DB_HOST is not set")
		return fmt.Errorf("PG_DB_HOST is not set")
	}
	port := os.Getenv("PG_DB_PORT")
	if port == "" {
		log.Printf("PG_DB_PORT is not set")
		return fmt.Errorf("PG_DB_PORT is not set")
	}
	user := os.Getenv("PG_DB_USER")
	if user == "" {
		log.Printf("PG_DB_USER is not set")
		return fmt.Errorf("PG_DB_USER is not set")
	}
	password := os.Getenv("PG_DB_PASSWORD")
	if password == "" {
		log.Printf("PG_DB_PASSWORD is not set")
		return fmt.Errorf("PG_DB_PASSWORD is not set")
	}

	dsn := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Plugins + "?sslmode=disable"
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn), pgdriver.WithTimeout(50*time.Second)))
	db := bun.NewDB(sqldb, pgdialect.New())
	defer db.Close()

	ctx := context.Background()
	exists, err := db.NewSelect().Model((*plugin.Plugin)(nil)).Where("name = ?", config.Name).Exists(ctx)
	if err != nil {
		log.Printf("%v", err)
		return err
	}

	if !exists {
		_, err = db.NewInsert().Model(&config).Exec(ctx)
		if err != nil {
			log.Printf("%v", err)
			return err
		}
	}
	return nil
}
