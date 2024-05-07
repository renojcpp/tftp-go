package main

import (
    "log"
    "flag"
    "github.com/renojcpp/tftp-go/tftp"
)

func main() {
    host := flag.String("host", "localhost", "The server host address")
	port := flag.Int("port", 8080, "The server port")
	flag.Parse()

    client, err := tftp.NewClient(*host, *port)
    if err != nil {
        log.SetFlags(0)
        log.Fatal("error creating client: ", err)
    }
    
    tftp.RunClientLoop(client)
}
