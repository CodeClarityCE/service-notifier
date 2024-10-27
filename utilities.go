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

	// Read message
	var dispatcherMessage map[string]string
	// map[string]string{
	// 	"package": pack.Key,
	// 	"version": pack.Versions[i].Key,
	// }
	err := json.Unmarshal([]byte(message), &dispatcherMessage)
	if err != nil {
		log.Printf("%v", err)
		return
	}

	// Start timer
	start := time.Now()

	// Start analysis
	_, _, err = startAnalysis(s, dispatcherMessage, config)
	if err != nil {
		log.Printf("%v", err)
		return
	}

	// Print time elapsed
	t := time.Now()
	elapsed := t.Sub(start)
	log.Println(elapsed)

	// // Send results
	// sbom_message := types_amqp.PluginDispatcherMessage{
	// 	AnalysisId: dispatcherMessage.AnalysisId,
	// 	Plugin:     config.Name,
	// }
	// data, _ := json.Marshal(sbom_message)
	// amqp_helper.Send("services_dispatcher", data)
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

	err = register(config)
	if err != nil {
		log.Printf("%v", err)
		return plugin.Plugin{}, err
	}

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
