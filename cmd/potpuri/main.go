package main

import (
	"context"
	"log"

	"potpuri/internal/app"
)

func main() {
	ctx := context.Background()
	factory := app.FactoryFromEnv()
	server, cleanup, err := factory.Build(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			log.Printf("cleanup failed: %v", err)
		}
	}()
	log.Printf("potpuri listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
