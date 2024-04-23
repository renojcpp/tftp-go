package main

import (
	"fmt"
	"github.com/renojcpp/tftp-go/tftp"
	"net"
)

const (
	defaultPort         = 69
	numberOfConnections = 10
)

func main() {

	clientSemaphore := NewSemaphore(numberOfConnections)
	conn, err := net.Listen("tcp", fmt.Sprint(defaultPort))
	if err != nil {
		fmt.Println("Error in listening")

	}

	for {
		conn, err := conn.Accept()
		if err != nil {
			fmt.Println("Error in accepting connection")

		}
		clientSemaphore.Acquire()
		go handleConnection(conn, clientSemaphore)
	}

}

func handleConnection(clientConnection net.Conn, s *Semaphore) {
	defer s.Release()
	defer clientConnection.Close()
	serverCon, _ := tftp.NewTFTPConnection(clientConnection, 0)
	serverCon.Handshake()
	serverCon.NextRequest()
}
