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
	errp := EncodeErr(str)

	_, err := s.conn.Write(errp)

	if err != nil {
		panic("Failed to send error")
	}
}

func (s ServerConnection) ReadWriteRequest(filename string) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)

	defer file.Close()
	if err != nil {
		return err
	}

	var ackn uint32 = 0
	done := false
	buf := make([]byte, 1024)
	for !done {
		ack := EncodeACK(ackn)
		_, err := s.conn.Write(ack)

		if err != nil {
			return err
		}

		ackn += 1
		n, err := s.readWriter.Read(buf)
		slice := buf[:n]
		if err != nil {
			return err
		}

		decoded := Packet(slice)

		switch decoded.Type() {
		case DAT:
			done, err = HandleDAT(decoded, ackn)
			if err != nil {
				return err
			}
			d := DATPacket(decoded)
			err = binary.Write(file, binary.NativeEndian, d.Data())
			if err != nil {
				return err
			}
		default:
			errs := "Unexpected header"
			s.SendError(errs)
			return errors.New(errs)
		}
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

	var resp bytes.Buffer
	_, err = s.readWriter.WriteTo(&resp)
	if err != nil {
		return err
	}

	decode := Packet(resp.Bytes())

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

	stream := NewDATStream(&buf)

	done := false
	var blockn uint32 = 1
	readbuf := make([]byte, 512)
	for !done {
		next, err := stream.Next()
		_, err = s.conn.Write(next)

		if err != nil {
			return err
		}

		if len(next.Data()) < 512 {
			done = true
		}

		n, err := s.readWriter.Read(readbuf)
		resp := readbuf[:n]
		if err != nil {
			return err
		}

		decoded := Packet(resp)

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
			if err == io.EOF {
				fmt.Fprintf(os.Stdout, "Connection closed")
			}
			break
		}

		decoded := Packet(req)
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
			fmt.Fprintf(os.Stderr, "Unexpected header %d", decoded.Type())
		}
	}

	s.conn.Close()
}
