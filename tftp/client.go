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
	rrq, err := NewRRQPacket(filename)

	// may need to do something extra about this
	_, err = c.Write(rrq)
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

		packet := Packet(resp)
		var ackn uint32 = 1
		if t, err := packet.Type(); err == nil {
			switch t {
			case DAT:
				d := DATPacket(packet)

				if err != nil {
					return nil, err
				}

				if len(d.Data) > 512 {
					return nil, errors.New("too bytes of data on DAT Packet")
				}

				if d.Size != uint32(len(d.Data)) {
					return nil, errors.New("Size header reporting incorrectl ")
				}

				if len(d.Data) < 512 {
					done = true
				}

				if d.Block != ackn {
					return nil, fmt.Errorf("Unexpected block data %d", ackn)
				}

				_, err = buffer.Write(d.Data)
				if err != nil {
					return nil, err
				}
			case ERR:
				d, err := decode[ERRPacket](packet)

				if err != nil {
					return nil, err
				}

				return nil, errors.New(d.Errstring)
			default:
				return nil, errors.New("Unknown packet received: " + t.String())
			}

			ack := NewACKPacket(ackn)
			p, err := Encode(ack)

			if err != nil {
				return nil, err
			}

			_, err = c.Write(p)
			if err != nil {
				return nil, err
			}

			ackn += 1
		} else {
			return nil, err
		}
	}

	return buffer.Bytes(), nil
}

// WriteWriteRequest creates an WRQPacket with the specified filename and
// conducts back and forth transfer of DAT packets with filestream data with
// receiving ACK packets. Code can be reused with WriteRRQStream.
func (c *Client) WriteWriteRequest(filename string, filestream []byte) error {
	wrq := NewWRQPacket(filename)
	packet, err := Encode(wrq)

	if err != nil {
		return err
	}

	_, err = c.Write(packet)

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

		packet = Packet(resp)
		var ackn uint32 = 0

		if t, err := packet.Type(); err == nil {
			switch t {
			case ACK:
				a, err := decode[ACKPacket](packet)

				if err != nil {
					return err
				}

				if a.Block != ackn {
					return fmt.Errorf("Unexpected block error %d", ackn)
				}
			case ERR:
				d, err := decode[ERRPacket](packet)

				if err != nil {
					return err
				}

				return errors.New(d.Errstring)
			default:
				return errors.New("Unknown packet received: " + t.String())
			}
			dat := stream.Next()
			p, err := Encode[DATPacket](dat)
			if err != nil {
				return err
			}

			_, err = c.Write(p)
			if err != nil {
				return err
			}

			if len(dat.Data) < 512 {
				done = true
			}
		} else {
			return err
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
