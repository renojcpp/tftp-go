package tftp

import (
	"bytes"
	"encoding/binary"
)

type HeaderId uint16

//go:generate stringer -Type=HeaderId
const (
	RRQ HeaderId = iota + 1
	WRQ
	DAT
	ACK
	ERR
)

const (
	EOS uint8 = iota
)

type tftpstruct interface {
	RRQPacket | WRQPacket | DATPacket | ACKPacket | ERRPacket
}

type Packet []byte
type RRQPacket Packet
type WRQPacket Packet
type DATPacket Packet
type ACKPacket Packet
type ERRPacket Packet

func (p Packet) Type() (HeaderId, error) {
	sl := bytes.NewReader(p[0:2])
	var h HeaderId

	err := binary.Read(sl, binary.BigEndian, h)

	if err != nil {
		return 0, err
	}

	return h, nil
}

func Encode[K tftpstruct](t *K) (Packet, error) {
	b := new(bytes.Buffer)

	err := binary.Write(b, binary.BigEndian, t)

	if err != nil {
		return nil, err
	}

	return Packet(b.Bytes()), nil
}

func decode[K tftpstruct](p Packet) (K, error) {
	reader := bytes.NewReader(p)
	var s K

	err := binary.Read(reader, binary.BigEndian, s)

	if err != nil {
		return s, err
	}

	return s, nil
}

type RRQPacket struct {
	Type     HeaderId
	Filename string
	Eos      uint8
}

func NewRRQPacket(s string) RRQPacket {
	buf := new(bytes.Buffer)

	d := []any{
		RRQ,
		s,
		EOS,
	}
	for _, v := range d {
		err := binary.Write(buf, binary.BigEndian, v)
		if err != nil {
			panic("failed to create ack packet")
		}
	}

	return buf.Bytes()
}

func NewWRQPacket(s string) WRQPacket {
	buf := new(bytes.Buffer)
	d := []any{
		WRQ,
		s,
		EOS,
	}

	for _, v := range d {
		err := binary.Write(buf, binary.BigEndian, v)
		if err != nil {
			panic("failed to create ack packet")
		}
	}

	return buf.Bytes()

}

func NewDATPacket(b, s uint32, data []byte) DATPacket {
	buf := new(bytes.Buffer)

	d := []any{
		DAT,
		b,
		s,
		data,
	}

	for _, v := range d {
		err := binary.Write(buf, binary.BigEndian, v)
		if err != nil {
			panic("failed to create ack packet")
		}
	}

	return buf.Bytes()
}

func NewACKPacket(b uint32) ACKPacket {
	buf := new(bytes.Buffer)

	d := []any{
		ACK,
		b,
	}

	for _, v := range d {
		err := binary.Write(buf, binary.BigEndian, v)
		if err != nil {
			panic("failed to create ack packet")
		}
	}

	return buf.Bytes()
}

func NewERRPacket(s string) ERRPacket {
	buf := new(bytes.Buffer)

	d := []any{
		ERR,
		s,
		EOS,
	}

	for _, v := range d {
		err := binary.Write(buf, binary.BigEndian, v)
		if err != nil {
			panic("failed to create ack packet")
		}
	}

	return buf.Bytes()

}
