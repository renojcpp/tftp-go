package tftp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
)

// todo: need to send errpackets

type ServerConnection struct {
	conn       net.Conn
	readWriter bufio.ReadWriter
	id         int
}

func NewTFTPConnection(c net.Conn, id int) *ServerConnection {
	writer := bufio.NewWriter(c)
	reader := bufio.NewReader(c)
	return &ServerConnection{
		c,
		*bufio.NewReadWriter(reader, writer),
		id,
	}
}

func (s ServerConnection) SendError(str string) {
	errp := EncodeWRR(str)

	_, err := s.conn.Write(errp)

	if err != nil {
		panic("Failed to send error")
	}
}

func (s ServerConnection) ReadWriteRequest(filename string) error {
	file, err := os.Create(filename)

	if err != nil {
		return err
	}

	defer file.Close()
	var buf bytes.Buffer
	var ackn uint32 = 0
	done := false

	for !done {
		ack := EncodeACK(ackn)
		_, err := s.conn.Write(ack)

		if err != nil {
			return err
		}

		ackn += 1
		resp, err := s.readWriter.ReadBytes('\000')

		if err != nil {
			return err
		}

		decoded := Packet(resp)

		switch decoded.Type() {
		case DAT:
			dat := DATPacket(decoded)

			if dat.Block() != ackn {
				s.SendError(fmt.Sprintf("Unrecognized block %d", dat.Block()))
				return fmt.Errorf("unrecognized block %d", dat.Block())
			}

			if dat.Size() != uint32(len(dat.Data())) {
				errs := "Inconsistent data sizes"
				s.SendError(errs)
				return errors.New(errs)
			}

			if dat.Size() < 512 {
				done = true
			}

			buf.Write(dat)
		default:
			errs := "Unexpected header"
			s.SendError(errs)
			return errors.New(errs)
		}
	}

	_, err = file.Write(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

func (s ServerConnection) Handshake() error {
	msg := "Hello!"
	packet := EncodeDAT(1, uint32(len(msg)), []byte(msg))

	_, err := s.conn.Write(packet)
	if err != nil {
		return err
	}

	resp, err := s.readWriter.ReadBytes('\000')
	if err != nil {
		return err
	}

	decode, err := Decode(resp)

	if err != nil {
		return err
	}

	switch decode.Type() {
	case ACK:
		return nil
	default:
		return errors.New("Unexpected block from handshake")
	}
}

func (s ServerConnection) ReadReadRequest(filename string) error {
	// assumes we already got the RRQ
	var buf bytes.Buffer

	if len(filename) == 0 {
		files, err := os.ReadDir(".")
		if err != nil {
			return err
		}

		for _, file := range files {
			buf.WriteString(file.Name())
			buf.WriteByte('\n')
		}
	} else {
		file, err := os.ReadFile(filename)
		if err != nil {
			s.SendError(err.Error())
			return err
		}
		buf.Write(file)
	}

	stream := NewDATStream(buf.Bytes())

	done := false
	var blockn uint32 = 1
	for !done {
		next := stream.Next()
		_, err := s.conn.Write(next)

		if err != nil {
			return nil
		}

		if len(next.Data()) < 512 {
			done = true
		}

		resp, err := s.readWriter.ReadBytes('\000')
		if err != nil {
			return nil
		}

		decoded, err := Decode(resp)

		if err != nil {
			return nil
		}

		switch decoded.Type() {
		case ACK:
			ack := ACKPacket(decoded)

			if ack.Block() != blockn {
				errs := fmt.Sprintf("Unexpected block number %d", ack.Block())
				s.SendError(errs)
				return errors.New(errs)
			}
		default:
			errs := fmt.Sprintf("Unexpected header %s", decoded.Type().String())
			s.SendError(errs)
			return errors.New(errs)
		}
	}

	return nil
}

func (s ServerConnection) NextRequest() {
	for {
		req, err := s.readWriter.ReadBytes('\000')
		if err != nil {
			break
		}

		decoded, err := Decode(req)
		switch decoded.Type() {
		case RRQ:
			rrq := RRQPacket(decoded)
			err = s.ReadReadRequest(rrq.Filename())
			if err != nil {
				// do something
			}
		case WRQ:
			wrq := WRQPacket(decoded)
			err = s.ReadWriteRequest(wrq.Filename())
		default:
			fmt.Fprintf(os.Stderr, "Unexpected block %d", decoded.Type())
		}
	}

	s.conn.Close()
}
