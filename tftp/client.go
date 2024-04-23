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
	_, err := c.conn.Write(rrq)
	if err != nil {
		return err
	}

	buf := make([]byte, 1024)

	done := false
	for !done {
		// read data
		n, err := c.reader.Read(buf)
		slice := buf[:n]
		if err != nil {
			return err
		}

		dec := Packet(slice)

		var ackn uint32 = 1
		switch dec.Type() {
		case DAT:
			done, err = HandleDAT(slice, ackn)
			if err != nil {
				return err
			}

			p := DATPacket(dec)
			err = binary.Write(w, binary.NativeEndian, p.Data())

			if err != nil {
				return err
			}
		case ERR:
			errp := ERRPacket(dec)

			return errors.New(errp.Errstring())
		default:
			return errors.New("Unknown packet received")
		}

		ack := EncodeACK(ackn)
		_, err = c.conn.Write(ack)
		if err != nil {
			return err
		}

		ackn += 1
	}

	return nil
}

// WriteWriteRequest creates an WRQPacket with the specified filename and
// conducts back and forth transfer of DAT packets with filestream data with
// receiving ACK packets. Code can be reused with WriteRRQStream.
func (c *Client) WriteWriteRequest(r io.Reader, filename string) error {
	wrq := EncodeWRQ(filename)
	_, err := c.conn.Write(wrq)

	if err != nil {
		return err
	}

	stream := NewDATStream(r)
	buf := make([]byte, 512)
	done := false
	for !done {
		n, err := c.reader.Read(buf)
		if err != nil {
			return err
		}


		resp := buf[:n]

		dec := Packet(resp)
		var ackn uint32 = 0
		switch dec.Type() {
		case ACK:
			ack := ACKPacket(dec)
			if ack.Block() != ackn {
				return fmt.Errorf("Unexpected block error %d", ackn)
			}
			fmt.Println("Acknowledge received")
		case ERR:
			e := ERRPacket(dec)
			
			return errors.New(e.Errstring())
		default:
			return errors.New("Unknown packet received ")
		}

		dat, err := stream.Next()

		_, err = c.conn.Write(dat)

		if err != nil {
			return err
		}
		fmt.Println("Data packet written to file")


		if len(dat.Data()) < 512 {
			done = true
			fmt.Println("End of data stream")
		}
	}
	return nil
}

// get runs the get command, which involves file transfer
// from a server
func (c *Client) get(args []argument) error {
	filename := args[0]

	if len(args) == 2 {
		filename = args[1]
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	defer file.Close()

	if err != nil {
		return err
	}

	err = c.WriteReadRequest(file, args[0])

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
	var b bytes.Buffer
	_, err := c.reader.WriteTo(&b)

	if err != nil {
		return err
	}

	decoded := Packet(b.Bytes())

	switch decoded.Type() {
	case DAT:
		dat := DATPacket(decoded)

		if dat.Block() != 1 {
			return fmt.Errorf("Unexpected block number: %d", dat.Block())
		}

		ack := EncodeACK(1)
		_, err := c.conn.Write(ack)

		if err != nil {
			return err
		}
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

	c := &Client{conn, *bufio.NewReader(conn), ok}

	return c, nil
}


func RunClientLoop(client *Client) {
    fmt.Println("TFTP Client: Enter commands (e.g., 'get filename.txt', 'put filename.txt', 'quit')")

    scanner := bufio.NewScanner(os.Stdin)

    for {
        fmt.Print("client> ")
        if !scanner.Scan() {
            break 
        }

        input := scanner.Text()
        if input == "quit" {
            fmt.Println("Exiting TFTP Client.")
            break 
        }

        command, err := NewCommand(input) 
        if err != nil {
            fmt.Println("Invalid command:", err)
            continue 
        }

        // Execute the command on the client
        err = client.Command(command)
        if err != nil {
            fmt.Println("Error executing command:", err)
        }
    }
}