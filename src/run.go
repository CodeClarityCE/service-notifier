package codeclarity

import "github.com/uptrace/bun"

type MyEdgeObject struct {
	From string `json:"_from"`
	To   string `json:"_to"`
}

// Entrypoint for the plugin
func Start(database *bun.DB, package_name string, version string, notification_key string) error {
	// // Start the plugin
	// var cursor driver.Cursor
	// querystring := `
	// LET sboms = (
	// 	FOR doc IN SBOMS
	// 		FILTER @package IN ATTRIBUTES(doc.workspaces["."].start_deps_constraints)
	// 			OR @package IN ATTRIBUTES(doc.workspaces["."].start_dev_deps_constraints)
	// 		RETURN doc._id
	// )

	// LET analyses = (
	// 	FOR sbom IN sboms
	// 		FOR v, e, p IN 1..1 INBOUND sbom GRAPH 'RESULTS_GRAPH'
	// 			RETURN v._id
	// )

	// LET projects = (
	// 	FOR analysis IN analyses
	// 		FOR v, e, p IN 1..1 INBOUND analysis GRAPH 'PROJECT_ANALYSIS_GRAPH'
	// 			RETURN DISTINCT v._id
	// )

	// LET organizations = (
	// 	FOR project IN projects
	// 		FOR v, e, p IN 1..1 INBOUND project GRAPH 'ORG_PROJECT_GRAPH'
	// 			RETURN DISTINCT v._id
	// )

	// FOR organization IN organizations
	// 	FOR v, e, p IN 1..1 OUTBOUND organization GRAPH 'ORG_MEMBERSHIP_GRAPH'
	// 		RETURN DISTINCT v._id
	// `
	// cursor, err := database.Query(
	// 	context.Background(),
	// 	querystring,
	// 	map[string]interface{}{"package": package_name},
	// )
	// if err != nil {
	// 	log.Fatalf("Query failed: %v", err)
	// }
	// defer cursor.Close()
	// var users []string
	// for {
	// 	var user string

	// 	_, err = cursor.ReadDocument(context.Background(), &user)

	// 	if driver.IsNoMoreDocuments(err) {
	// 		break
	// 	} else if err != nil {
	// 		log.Fatalf("Doc returned: %v", err)
	// 	} else {
	// 		users = append(users, user)
	// 	}
	// }

	// if len(users) == 0 {
	// 	// log.Printf("No users found for package %s version %s", package_name, version)
	// 	col, err := database.Collection(context.Background(), dbhelper.Config.Collection.Notifications)
	// 	if err != nil {
	// 		log.Fatalf("Failed to select collection: %v", err)
	// 	}
	// 	// log.Printf("Removing notification %s", notification_key)
	// 	_, err = col.RemoveDocument(context.Background(), notification_key)
	// 	if err != nil {
	// 		log.Fatalf("Failed to remove document: %v", err)
	// 	}
	// 	return nil
	// }

	// graph, err := dbhelper.GetGraph(dbhelper.Config.Database.Results, dbhelper.Config.Graph.User_notifications)
	// if err != nil {
	// 	log.Printf("%v", err)
	// }

	// edgeCollection, _, err := graph.EdgeCollection(context.Background(), dbhelper.Config.Edge.User_notifications)
	// if err != nil {
	// 	log.Printf("Failed to select edge collection: %v", err)
	// }
	// edges := []MyEdgeObject{}
	// for _, user := range users {
	// 	edge := MyEdgeObject{
	// 		From: dbhelper.Config.Collection.Notifications + "/" + notification_key,
	// 		To:   user,
	// 	}
	// 	edges = append(edges, edge)
	// }
	// log.Printf("Edges: %v", edges)
	// _, _, err = edgeCollection.CreateDocuments(context.Background(), edges)
	// if err != nil {
	// 	log.Fatalf("Failed to create edge document: %v", err)
	// 	return err
	// }

	return nil
}
