package tftp

import (
	"bytes"
	"encoding/gob"
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
	enc := gob.NewDecoder(sl)
	var h HeaderId

	err := enc.Decode(&h)

	if err != nil {
		return 0, err
	}

	return h, nil
}

func Encode[K tftpstruct](t *K) (Packet, error) {
	b := new(bytes.Buffer)
	enc := gob.NewEncoder(b)
	err := enc.Encode(*t)

	if err != nil {
		return nil, err
	}

	return Packet(b.Bytes()), nil
}

func decode[K tftpstruct](p Packet) (K, error) {
	reader := bytes.NewReader(p)
	dec := gob.NewDecoder(reader)
	var s K
	err := dec.Decode(&s)

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
	return (*RRQPacket)(NewWRQPacket(s))
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
