package main

import (
	"flag"
	"log"
	"net"

	"github.com/renojcpp/tftp-go/tftp"
)

func main() {
	rootPath := flag.String("rootPath", "", "The server host address")
	port := flag.String("port", "8080", "The server port")
	flag.Parse()

	listener, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		log.Fatal("Error starting server:", err)
	}
	server := tftp.NewServer(listener, 5, *port, *rootPath)
	server.Start()
}
