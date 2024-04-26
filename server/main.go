package main

import (
	"log"
	"net"
)

func main() {
	port := "8080"

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal("Error starting server:", err)
	}
	server := NewServer(listener, 10, port)
	server.Start()

}
