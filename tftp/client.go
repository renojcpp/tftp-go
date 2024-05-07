package tftp

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

type cstatus int

const (
	ok cstatus = iota
	ready
	destroyed
)

type Client struct {
	conn       net.Conn
	reader     bufio.Reader
	status     cstatus
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
	c.status = destroyed
	return c.conn.Close()
}

// WriteReadRequest creates an RRQ packet with a filename argument then
// conducts back and forth delivery of ACK and DAT packets with the server.
// Code can be refactored to share code with WriteWRQStream
func (c *Client) WriteReadRequest(w io.Writer, filename string) error {
	rrq := EncodeRRQ(filename)

	err := c.SendPacket(rrq)
	if err != nil {
		rrqPackErr := &throwErrors{
			err, "sending read request packet",
		}
		return rrqPackErr
	}

	done := false
	var ackn uint32 = 1
	for !done {
		dec, err := c.ReceivePacket()
		if err != nil {
			receivePackErr := &throwErrors{
				err, "receiving packet",
			}
			return receivePackErr
		}

		switch dec.Type() {
		case DAT:
			done, err = HandleDAT(dec, ackn)
			if err != nil {
				datPackErr := &throwErrors{
					err, "Handling data packet",
				}
				c.conn.Close()
				return datPackErr
			}

			p := DATPacket(dec)
			if p.Size() > 512{
				c.conn.Close()
				return &throwErrors{
					err, "Max Block Size Exceeded",
				}
			}
			err = binary.Write(w, binary.NativeEndian, p.Data())

			if err != nil {
				writingErr := &throwErrors{
					err, "writing data",
				}
				return writingErr
			}
			fmt.Println("Data block #", ackn, "read")
		case ERR:
			errp := ERRPacket(dec)
			return errors.New(errp.Errstring())
		default:
			c.conn.Close()
			return errors.New("unknown packet received")
		}

		ack := EncodeACK(ackn)
		err = c.SendPacket(ack)
		if err != nil {
			ackPackErr := &throwErrors{
				err, "sending ACK Packet",
			}
			return ackPackErr
		}
		fmt.Println("Acknowledge block #", ackn, "sent")

		ackn += 1
		if done {
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
		wrqPackErr := &throwErrors{
			err, "sending write request packet",
		}
		return wrqPackErr
	}

	stream := NewDATStream(r)
	done := false
	var ackn uint32 = 0
	for !done {
		dec, err := c.ReceivePacket()
		if err != nil {
			receivePackErr := &throwErrors{
				err, "receiving Packet",
			}
			return receivePackErr
		}

		switch dec.Type() {
		case ACK:
			ack := ACKPacket(dec)
			if ack.Block() != ackn {
				c.conn.Close()
				return fmt.Errorf("unexpected block error %d", ackn)
			}
			fmt.Println("Acknowledge received block #", ackn)
			ackn++
		case ERR:
			e := ERRPacket(dec)
			return errors.New(e.Errstring())
		default:
			c.conn.Close()
			return errors.New("unknown packet received ")
		}

		dat, err := stream.Next()
		if err != nil {
			nextDataErr := &throwErrors{
				err, "Retrieving data",
			}
			return nextDataErr
		}
		err = c.SendPacket(Packet(dat))

		if err != nil {
			datPackErr := &throwErrors{
				err, "Sending data packet",
			}
			return datPackErr
		}
		fmt.Println("Data block #", ackn, "sent")

		if len(dat.Data()) < 512 {
			fmt.Println("End of data stream")
			dec, err := c.ReceivePacket()
			if err != nil {
				finalAckErr := &throwErrors{
					err, "Receiving final ACK",
				}
				return finalAckErr
			}
			switch dec.Type() {
			case ACK:
				ack := ACKPacket(dec)
				if ack.Block() != ackn {
					c.conn.Close()
					return fmt.Errorf("unexpected block error %d", ackn)
				}
				fmt.Println("Acknowledge received block #", ackn)
				ackn++
			case ERR:
				e := ERRPacket(dec)
				return errors.New(e.Errstring())
			default:
				c.conn.Close()
				return errors.New("unknown packet received ")
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
		getErr := &throwErrors{
			err, "writeRead request",
		}
		return getErr
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		openErr := &throwErrors{
			err, "opening file",
		}
		return openErr
	}
	defer file.Close()

	_, err = buffer.WriteTo(file)
	if err != nil {
		writeErr := &throwErrors{
			err, "writing to file",
		}
		return writeErr
	}

	return nil
}

func (c *Client) put(args []argument) error {
	// read the file
	file, err := os.Open(args[0])

	if err != nil {
		openFileErr := &throwErrors{
			err, "opening file",
		}
		return openFileErr
	}
	defer file.Close()

	filename := args[0]
	if len(args) == 2 {
		filename = args[1]
	}

	// send bytes of the file
	err = c.WriteWriteRequest(file, filename)

	if err != nil {
		getErr := &throwErrors{
			err, "write request",
		}
		return getErr
	}

	return nil
}

func (c *Client) dir() error {
	err := c.WriteReadRequest(os.Stdout, "")

	if err != nil {
		dirErr := &throwErrors{
			err, "DIR request",
		}
		return dirErr
	}

	return nil
}

func (c *Client) Handshake() error {
	buf := make([]byte, 512)
	_, err := c.reader.Read(buf)

	if err != nil {
		handshakeErr := &throwErrors{
			err, "Handshake",
		}
		return handshakeErr
	}

	decoded := Packet(buf)
	switch decoded.Type() {
	case DAT:
		dat := DATPacket(decoded)

		if dat.Block() != 1 {
			return fmt.Errorf("unexpected block number: %d", dat.Block())
		}
		fmt.Println("Handshake Dat block received")

		ack := EncodeACK(1)
		_, err := c.conn.Write(ack)

		if err != nil {
			handshakeACKErr := &throwErrors{
				err, "Handshake Acknowledge",
			}
			return handshakeACKErr
		}
		fmt.Println("Acknowledge of handshake sent")

		err = c.ExchangeKeys()
		if err != nil {
			fmt.Println("Error exchanging keys: ", err)
			return err
		}

		return nil
	case ERR:
		errPacket := ERRPacket(decoded)
		return &throwErrors{
			errors.New(errPacket.Errstring()),
			"error packet received",
		}
	default:
		return errors.New("unexpected header")
	}

}

func NewClient(hostname string, port int) (*Client, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", hostname, port))
	if err != nil {
		newClientErr := &throwErrors{
			err, "Creating Client",
		}
		return nil, newClientErr
	}

	tcpConn, connOk := conn.(*net.TCPConn)
	if !connOk {
		conn.Close()
		return nil, fmt.Errorf("connection is not TCP")
	}

	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(3 * time.Minute)

	encryption, err := NewEncryptionManager()
	if err != nil {
		encryptErr := &throwErrors{
			err, "Encryption",
		}
		return nil, encryptErr
	}

	c := &Client{conn, *bufio.NewReader(conn), ok, encryption}

	if err := c.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	return c, nil
}

func RunClientLoop(client *Client) error {
	fmt.Println("TFTP Client Started.\nEnter commands ('get filename', 'put filename', 'quit', 'dir')")
	scanner := bufio.NewScanner(os.Stdin)

	for {
		if client.status == destroyed {
			fmt.Println("Connection Terminated")
			break
		}

		fmt.Print("\nclient> ")
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
			// if netErr, ok := err.(net.Error); ok {
			// 	if !netErr.Temporary() || netErr.Timeout() {
			// 		fmt.Println("Coonnection lost:", err)
			// 		return err
			// 	}
			// }
			fmt.Println("Error executing command:", err)
		}

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
		receivePackErr := &throwErrors{
			err, "Receiving Packet",
		}
		return nil, receivePackErr
	}
	packet, err := decryptPacket(buf[:n], c.encryption.sharedKey)
	if err != nil {
		decryptErr := &throwErrors{
			err, "Decrypting Packet",
		}
		return nil, decryptErr
	}
	return Packet(packet), nil
}

func (c *Client) SendPacket(packet Packet) error {
	encryptedPacket, err := encryptPacket(packet, c.encryption.sharedKey)
	if err != nil {
		encryptErr := &throwErrors{
			err, "Encrypting Packet",
		}
		return encryptErr
	}
	_, err = c.conn.Write(encryptedPacket)
	if err != nil {
		writeEncryptErr := &throwErrors{
			err, "Writing to encrypted packet",
		}
		return writeEncryptErr
	}
	return nil
}

func (client *Client) ExchangeKeys() error {
	fmt.Println("Exchanging Public Key")

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

	fmt.Printf("Key Succesfully exchanged\n\n")
	return nil
}

func (c *Client) CompleteKeyExchange(publicKeyPEM []byte) error {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("invalid public key PEM")
	}

	serverPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		publicKeyErr := &throwErrors{
			err, "Server Public Key",
		}
		return publicKeyErr
	}

	symmetricKey := make([]byte, 32)
	_, err = rand.Reader.Read(symmetricKey)
	if err != nil {
		symmeKeyErr := &throwErrors{
			err, "Symmetric Key Reading",
		}
		return symmeKeyErr
	}

	encryptedSymmetricKey, err := rsaEncrypt(serverPublicKey.(*rsa.PublicKey), symmetricKey)
	if err != nil {
		rsaEncryptErr := &throwErrors{
			err, "RSA Encryption",
		}
		return rsaEncryptErr
	}

	_, err = c.conn.Write(encryptedSymmetricKey)
	c.encryption.sharedKey = symmetricKey
	if err != nil {
		encryptedSymmKeyErr := &throwErrors{
			err, "Encrypted Symmtetric Key Writing",
		}
		return encryptedSymmKeyErr
	}
	return nil
}
