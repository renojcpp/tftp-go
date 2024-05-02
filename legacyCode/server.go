package main

import (
	"fmt"
	"net"

	"github.com/renojcpp/tftp-go/tftp"
)

type Server struct {
	listener    net.Listener
	clientLimit *Clientlimit
	port        string
}

func NewServer(listener net.Listener, maxClients int, port string) *Server {
	return &Server{
		listener:    listener,
		clientLimit: NewClientLimit(maxClients),
		port:        port,
	}
}

func (s *Server) Start() {
	fmt.Println("Server listening.....")
	defer s.listener.Close()
	for {
		if s.clientLimit.increaseClientCount() != nil {
			fmt.Println("Client limit has been reached!")
			continue

		}
		go s.HandleConnection()

	}
}

func (s *Server) HandleConnection() {
	defer s.clientLimit.decreaseClientCount()
	tftp.StartServer(s.listener, s.port)

}
