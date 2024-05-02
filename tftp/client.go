package tftp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"crypto/x509"
	"encoding/pem"
	"crypto/rand"
	"crypto/rsa"
	"time"
)

type cstatus int

const (
	ok cstatus = iota
	ready
	destroyed
)

type Client struct {
	conn   net.Conn
	reader bufio.Reader
	status cstatus
	encryption *EncryptionManager 
}

func (client *Client) Command(c *Command) error {
	switch c.command {
	case Dir:
		return client.dir()
	case Get:
		return client.get(c.args)
	case Put:
		return client.put(c.args)
	case Quit:
		return client.quit()
	default:
		return errors.New("Unrecognized command: " + string(c.command))
	}
}

func (c *Client) quit() error {
	return c.conn.Close()
}

// WriteReadRequest creates an RRQ packet with a filename argument then
// conducts back and forth delivery of ACK and DAT packets with the server.
// Code can be refactored to share code with WriteWRQStream
func (c *Client) WriteReadRequest(w io.Writer, filename string) error {
	rrq := EncodeRRQ(filename)

	// may need to do something extra about this
	err := c.SendPacket(rrq)
	if err != nil {
		return err
	}

	done := false
	var ackn uint32 = 1
	for !done {
		dec, err := c.ReceivePacket()
		if err != nil {
			return err
		}

		switch dec.Type() {
		case DAT:
			done, err = HandleDAT(dec, ackn)
			if err != nil {
				return err
			}

			p := DATPacket(dec)
			err = binary.Write(w, binary.NativeEndian, p.Data())

			if err != nil {
				return err
			}
			fmt.Println("Data block #", ackn, "read")
		case ERR:
			errp := ERRPacket(dec)
			return errors.New(errp.Errstring())
		default:
			return errors.New("Unknown packet received")
		}

		ack := EncodeACK(ackn)
		err = c.SendPacket(ack)
		if err != nil {
			return err
		}
		fmt.Println("Acknowledge block #", ackn, "sent")

		ackn += 1
		if done{
			fmt.Println("Read Request fulfilled. End of data stream.")
		}
	}

	return nil
}

// WriteWriteRequest creates an WRQPacket with the specified filename and
// conducts back and forth transfer of DAT packets with filestream data with
// receiving ACK packets. Code can be reused with WriteRRQStream.
func (c *Client) WriteWriteRequest(r io.Reader, filename string) error {
	wrq := EncodeWRQ(filename)
	err := c.SendPacket(wrq)
	if err != nil {
		return err
	}

	stream := NewDATStream(r)
	done := false
	var ackn uint32 = 0
	for !done {
		dec, err := c.ReceivePacket()

		switch dec.Type() {
		case ACK:
			ack := ACKPacket(dec)
			if ack.Block() != ackn {
				return fmt.Errorf("Unexpected block error %d", ackn)
			}
			fmt.Println("Acknowledge received block #", ackn)
			ackn++
		case ERR:
			e := ERRPacket(dec)
			return errors.New(e.Errstring())
		default:
			return errors.New("Unknown packet received ")
		}

		dat, err := stream.Next()
		err = c.SendPacket(Packet(dat)) 

		if err != nil {
			return err
		}
		fmt.Println("Data block #", ackn, "sent")


		if len(dat.Data()) < 512 {
			fmt.Println("End of data stream")
			//THis checks for final ack
			//Code is redudant to above so may want to modularize
			dec, err := c.ReceivePacket()
			if err != nil {
				return err
			}
			switch dec.Type() {
			case ACK:
				ack := ACKPacket(dec)
				if ack.Block() != ackn {
					return fmt.Errorf("Unexpected block error %d", ackn)
				}
				fmt.Println("Acknowledge received block #", ackn)
				ackn++
			case ERR:
				e := ERRPacket(dec)
				return errors.New(e.Errstring())
			default:
				return errors.New("Unknown packet received ")
			}
			done = true
		}
	}
	return nil
}

// get runs the get command, which involves file transfer
// from a server
func (c *Client) get(args []argument) error {
	var buffer bytes.Buffer
	filename := args[0]

	if len(args) == 2 {
		filename = args[1]
	}

	err := c.WriteReadRequest(&buffer, args[0])
	if err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = buffer.WriteTo(file)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) put(args []argument) error {
	// read the file
	file, err := os.Open(args[0])

	if err != nil {
		return err
	}

	filename := args[0]
	if len(args) == 2 {
		filename = args[1]
	}

	// send bytes of the file
	err = c.WriteWriteRequest(file, filename)

	if err != nil {
		return err
	}

	return nil
}

func (c *Client) dir() error {
	err := c.WriteReadRequest(os.Stdout, "")

	if err != nil {
		return err
	}

	return nil
}

func (c *Client) Handshake() error {
	buf := make([]byte, 512)
	_, err := c.reader.Read(buf)

	if err != nil {
		return err
	}

	decoded := Packet(buf)
	switch decoded.Type() {
	case DAT:
		dat := DATPacket(decoded)

		if dat.Block() != 1 {
			return fmt.Errorf("Unexpected block number: %d", dat.Block())
		}
		fmt.Println("Handshake dat block # 1 received")

		ack := EncodeACK(1)
		_, err := c.conn.Write(ack)

		if err != nil {
			return err
		}
		fmt.Println("Acknowledge of block # 1 sent")
		return nil
	default:
		return errors.New("unexpected header")
	}
}

func NewClient(hostname string, port int) (*Client, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", hostname, port))
	if err != nil {
		return nil, err
	}

	encryption, err := NewEncryptionManager()
	if err != nil {
		return nil, err
	}

	c := &Client{conn, *bufio.NewReader(conn), ok, encryption}

	if err := c.Handshake(); err != nil {
        conn.Close()
        return nil, fmt.Errorf("handshake failed: %v", err)
    }

	return c, nil
}

// func (client *Client) ConnectionIsNotOpen() bool{
// 	_, err := client.conn.Write([]byte{0})  //Test Byte
// 	if err != nil {
// 		return true
// 	}
// 	return false 
// }

func RunClientLoop(client *Client) error {
	time.Sleep(1 * time.Second)
	err := client.ExchangeKeys()
	if err != nil{
		fmt.Println("Error exchanging keys: ", err)
		return err
	}
    fmt.Println("TFTP Client: Enter commands (e.g., 'get filename.txt', 'put filename.txt', 'quit')")
    scanner := bufio.NewScanner(os.Stdin)

    for {
        fmt.Print("client> ")
        if !scanner.Scan() {
            break 
        }

        input := scanner.Text()
        command, err := NewCommand(input) 
        if err != nil {
            fmt.Println("Invalid command:", err)
            continue 
        }

        err = client.Command(command)
        if err != nil {
            fmt.Println("Error executing command:", err)
        }

		// if client.ConnectionIsNotOpen(){
		// 	fmt.Println("Connection Terminated")
		// 	break
		// }
    }
	return nil
}


/*
Packet Sending and Encryption methods below
*/

func (c *Client) ReceivePacket() (Packet, error) {
	buf := make([]byte, 1024)
	n, err := c.reader.Read(buf)
	if err != nil {
		return nil, err
	}
	packet, err := decryptPacket(buf[:n], c.encryption.sharedKey)
	if err != nil {
		return nil, err
	}
	return Packet(packet), nil
}


func (c *Client) SendPacket(packet Packet) error {
	encryptedPacket, err := encryptPacket(packet, c.encryption.sharedKey)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(encryptedPacket)
	if err != nil {
		return err
	}
	return nil
}

func(client *Client) ExchangeKeys() error{
	fmt.Println("Exchanging Public Key")

	keyRQ := EncodeKeyRQ()
	_, err := client.conn.Write(keyRQ)
	if err != nil {
		return err
	}

	publicKeyPEM := []byte{}
	tempBuffer := make([]byte, 256)
	for {
		n, err := client.reader.Read(tempBuffer) 
		if err != nil {
			return fmt.Errorf("failed to read server public key: %w", err)
		}

		publicKeyPEM = append(publicKeyPEM, tempBuffer[:n]...)

		if bytes.HasSuffix(publicKeyPEM, []byte("\n")) {
			break
		}
	}
	
	if err := client.CompleteKeyExchange(publicKeyPEM); err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}

	fmt.Println("Key Succesfully exchanged")
	return nil
}

func (c *Client) CompleteKeyExchange(publicKeyPEM []byte) error {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("invalid public key PEM")
	}

	serverPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	symmetricKey := make([]byte, 32) 
	_, err = rand.Reader.Read(symmetricKey)
	if err != nil {
		return err
	}

	encryptedSymmetricKey, err := rsaEncrypt(serverPublicKey.(*rsa.PublicKey), symmetricKey)
	if err != nil {
		return err
	}

	_, err = c.conn.Write(encryptedSymmetricKey)
	c.encryption.sharedKey = symmetricKey
	return err
}