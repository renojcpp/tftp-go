package main

import (
	"flag"
	"log"
	"net"

	"github.com/renojcpp/tftp-go/tftp"
)

func main() {
	rootPath := flag.String("rootPath", "", "The server file system root")
	port := flag.String("port", "8080", "The server port")
	address := flag.String("address", "0.0.0.0", "The server address")
	flag.Parse()

	listener, err := net.Listen("tcp", *address+":"+*port)
	if err != nil {
		log.Fatal("Error starting server:", err)
	}

	tcpAddr := listener.Addr().(*net.TCPAddr)
	log.Println("Server is running on:", tcpAddr.IP.String())

	server := tftp.NewServer(listener, 5, *port, *rootPath)
	server.Start()
}
