package tftp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
)

type cstatus int

const (
	ok cstatus = iota
	ready
	destroyed
)

type Client struct {
	net.Conn
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
	return c.Close()
}

// WriteReadRequest creates an RRQ packet with a filename argument then
// conducts back and forth delivery of ACK and DAT packets with the server.
// Code can be refactored to share code with WriteWRQStream
func (c *Client) WriteReadRequest(filename string) ([]byte, error) {
	rrq := EncodeRRQ(filename)

	// may need to do something extra about this
	_, err := c.Write(rrq)
	if err != nil {
		return nil, err
	}

	buffer := new(bytes.Buffer)

	done := false
	for !done {
		// read data
		resp, err := io.ReadAll(c)

		if err != nil {
			return nil, err
		}
		dec, err := Decode(resp)

		if err != nil {
			return nil, err
		}

		packet := Packet(dec)
		var ackn uint32 = 1
		switch packet.Type() {
		case DAT:
			if err != nil {
				return nil, err
			}

			dat := DATPacket(packet)

			if len(dat.Data()) > 512 {
				return nil, errors.New("too bytes of data on DAT Packet")
			}

			if dat.Size() != uint32(len(dat.Data())) {
				return nil, errors.New("Size header reporting incorrect ")
			}

			if len(dat.Data()) < 512 {
				done = true
			}

			if dat.Block() != ackn {
				return nil, fmt.Errorf("Unexpected block data %d", ackn)
			}

			buffer.Write(dat.Data())
		case ERR:
			errp := ERRPacket(packet)

			return nil, errors.New(errp.Errstring())
		default:
			return nil, errors.New("Unknown packet received")
		}

		ack := EncodeACK(ackn)

		if err != nil {
			return nil, err
		}

		_, err = c.Write(ack)
		if err != nil {
			return nil, err
		}

		ackn += 1
	}

	return buffer.Bytes(), nil
}

// WriteWriteRequest creates an WRQPacket with the specified filename and
// conducts back and forth transfer of DAT packets with filestream data with
// receiving ACK packets. Code can be reused with WriteRRQStream.
func (c *Client) WriteWriteRequest(filename string, filestream []byte) error {
	wrq := EncodeWRQ(filename)

	_, err := c.Write(wrq)

	if err != nil {
		return err
	}

	stream := NewDATStream(filestream)
	done := false
	for !done {
		// read ack
		resp, err := io.ReadAll(c)

		if err != nil {
			return err
		}

		dec, err := Decode(resp)

		if err != nil {
			return err
		}

		var ackn uint32 = 0
		packet := Packet(dec)
		switch packet.Type() {
		case ACK:
			ack := ACKPacket(packet)
			if ack.Block() != ackn {
				return fmt.Errorf("Unexpected block error %d", ackn)
			}

		case ERR:
			e := ERRPacket(packet)

			if err != nil {
				return err
			}

			return errors.New(e.Errstring())
		default:
			return errors.New("Unknown packet received ")
		}

		dat := stream.Next()

		_, err = c.Write(dat)

		if err != nil {
			return err
		}

		if len(dat.Data()) < 512 {
			done = true
		}
	}
	return nil
}

// get runs the get command, which involves file transfer
// from a server
func (c *Client) get(args []argument) error {
	rawbytes, err := c.WriteReadRequest(args[0])
	if err != nil {
		return err
	}

	// write the bytes to a file
	filename := args[0]

	if len(args) == 2 {
		filename = args[1]
	}

	return nil
}

func (c *Client) put(args []argument) error {
	// read the file

	// send bytes of the file
}

func (c *Client) dir() error {
	output, err := c.WriteReadRequest("")

	if err != nil {
		return err
	}

	fmt.Printf("%s\n", output)
	return nil
}

func (c *Client) handshake() error {
}

func NewClient(hostname string, port int) (*Client, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", hostname, port))

	if err != nil {
		return nil, err
	}

	c := &Client{conn, ok}

	if err := c.handshake(); err != nil {
		return nil, err
	}

	return c, nil
}

func WrapConnection(n *net.Conn) *Client {
	return &Client{*n, ok}
}
