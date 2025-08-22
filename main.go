// Package main provides the entry point for the notifier service.
package main

import (
	"log"

	"github.com/CodeClarityCE/utility-types/boilerplates"
	amqp "github.com/rabbitmq/amqp091-go"
)

// NotifierService wraps the ServiceBase with notifier-specific functionality
type NotifierService struct {
	*boilerplates.ServiceBase
}

// CreateNotifierService creates a new NotifierService
func CreateNotifierService() (*NotifierService, error) {
	base, err := boilerplates.CreateServiceBase()
	if err != nil {
		return nil, err
	}

	service := &NotifierService{
		ServiceBase: base,
	}

	// Setup queue handler
	service.AddQueue("service_notifier", true, service.handleMessage)

	return service, nil
}

// handleMessage handles messages from service_notifier queue
func (s *NotifierService) handleMessage(d amqp.Delivery) {
	handleNotification(s.DB, d)
}

func main() {
	service, err := CreateNotifierService()
	if err != nil {
		log.Fatalf("Failed to create notifier service: %v", err)
	}
	defer service.Close()

	log.Printf("Starting Notifier Service...")
	if err := service.StartListening(); err != nil {
		log.Fatalf("Failed to start listening: %v", err)
	}

	log.Printf("Notifier Service started")
	service.WaitForever()
}