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

func NewRRQPacket(s string) *RRQPacket {
	p := (*RRQPacket)(NewWRQPacket(s))
	p.Type = RRQ
	return p
}

type WRQPacket struct {
	Type     HeaderId
	Filename string
	Eos      uint8
}

func NewWRQPacket(s string) *WRQPacket {
	return &WRQPacket{
		WRQ,
		s,
		EOS,
	}
}

type DATPacket struct {
	Type  HeaderId
	Block uint32
	Size  uint32
	Data  []byte
}

func NewDATPacket(b, s uint32, data []byte) *DATPacket {
	return &DATPacket{
		DAT,
		b,
		s,
		data,
	}
}

type ACKPacket struct {
	Type  HeaderId
	Block uint32
}

func NewACKPacket(b uint32) *ACKPacket {
	return &ACKPacket{
		ACK,
		b,
	}
}

type ERRPacket struct {
	Type      HeaderId
	Errstring string
	Eos       uint8
}

func NewERRPacket(s string) *ERRPacket {
	return &ERRPacket{
		ERR,
		s,
		EOS,
	}
}
