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

func (p Packet) Type() HeaderId {
	sl := bytes.NewReader(p[0:2])
	enc := gob.NewDecoder(sl)
	var h HeaderId

	err := enc.Decode(&h)

	if err != nil {
		panic("Failed to read type")
	}

	return h
}

type RRQPacket struct {
	Type     HeaderId
	Filename string
	Eos      uint8
}

func Encode[K tftpstruct](t *K) Packet {
	b := new(bytes.Buffer)
	enc := gob.NewEncoder(b)
	err := enc.Encode(*t)

	if err != nil {
		panic("Failed to generate packet ")
	}

	return Packet(b.Bytes())
}

func Decode[K tftpstruct](p Packet) K {
	reader := bytes.NewReader(p)
	dec := gob.NewDecoder(reader)
	var s K
	err := dec.Decode(&s)

	if err != nil {
		panic("Failed to decode packet")
	}

	return s
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
