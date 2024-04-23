package main

import (
    "log"
    "github.com/renojcpp/tftp-go/tftp"
    "net"
)

func main() {
    port := "8080"

    listener, err := net.Listen("tcp", ":"+ port )
    if err != nil {
        log.Fatal("Error starting server:", err)
    }

    tftp.StartServer(listener, port)
}