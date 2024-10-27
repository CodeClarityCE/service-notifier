package main

import (
	"database/sql"
	"log"
	"os"
	"time"

	service "github.com/CodeClarityCE/service-notifier/src"
	amqp_helper "github.com/CodeClarityCE/utility-amqp-helper"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	plugin "github.com/CodeClarityCE/utility-types/plugin_db"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// Define the arguments you want to pass to the callback function
type Arguments struct {
	codeclarity *bun.DB
	knowledge   *bun.DB
}

// main is the entry point of the program.
// It reads the configuration, initializes the necessary databases and graph,
// and starts listening on the queue.
func main() {
	config, err := readConfig()
	if err != nil {
		log.Printf("%v", err)
		return
	}

	host := os.Getenv("PG_DB_HOST")
	if host == "" {
		log.Printf("PG_DB_HOST is not set")
		return
	}
	port := os.Getenv("PG_DB_PORT")
	if port == "" {
		log.Printf("PG_DB_PORT is not set")
		return
	}
	user := os.Getenv("PG_DB_USER")
	if user == "" {
		log.Printf("PG_DB_USER is not set")
		return
	}
	password := os.Getenv("PG_DB_PASSWORD")
	if password == "" {
		log.Printf("PG_DB_PASSWORD is not set")
		return
	}

	dsn := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Results + "?sslmode=disable"
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn), pgdriver.WithTimeout(50*time.Second)))
	db_codeclarity := bun.NewDB(sqldb, pgdialect.New())
	defer db_codeclarity.Close()

	dsn_knowledge := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	args := Arguments{
		codeclarity: db_codeclarity,
		knowledge:   db_knowledge,
	}

	// Start listening on the queue
	amqp_helper.Listen("service_"+config.Name, callback, args, config)
}

// startAnalysis is a function that performs the analysis for codeclarity plugin.
// It takes the following parameters:
// - args: Arguments for the analysis.
// - dispatcherMessage: Dispatcher plugin message.
// - config: Plugin configuration.
// - analysis_document: Analysis document.
// It returns a map[string]any containing the result of the analysis, the analysis status, and an error if any.
func startAnalysis(args Arguments, dispatcherMessage map[string]string, config plugin.Plugin) (map[string]any, codeclarity.AnalysisStatus, error) {
	// Do your analysis here
	output := service.Start(args.codeclarity, dispatcherMessage["package"], dispatcherMessage["version"], dispatcherMessage["key"])

	// Prepare the result to store in step
	// Usually we store the key of the result document that was just created
	// The other plugins will use this key
	result := make(map[string]any)
	result["output"] = output

	// Set the status of the analysis
	status := codeclarity.SUCCESS

	// The output is always a map[string]any
	return result, status, nil
}
