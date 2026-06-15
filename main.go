package main

import (
	"fmt"
	"os"
	"snowden/api"
	"snowden/config"
)

const DefaultPort = ":80"

func main() {
	config.LoadEnv()

	port := DefaultPort
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	server := api.NewApiServer(port)
	fmt.Println("Starting server on port", port)

	server.Run()
}
