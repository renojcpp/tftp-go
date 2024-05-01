package main

import (
	"log"
	"net"
	// "fmt"
	"github.com/renojcpp/tftp-go/tftp"
)

func main() {
	port := "8080"

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal("Error starting server:", err)
	}
	server := tftp.NewServer(listener, 10, port)
	server.Start()
}
