package main

import (
    "log"
    "github.com/renojcpp/tftp-go/tftp"
)

func main() {
    client, err := tftp.NewClient("localhost", 8080)
    if err != nil {
        log.Fatal("Error creating client:", err)
    }
    
    tftp.RunClientLoop(client)
}
