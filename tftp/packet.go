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

type RRQPacket struct {
	Type     HeaderId
	Filename string
	Eos      uint8
}

func encode[K tftpstruct](t *K) Packet {
	b := new(bytes.Buffer)
	enc := gob.NewEncoder(b)
	err := enc.Encode(*t)

	if err != nil {
		panic("Failed to generate packet ")
	}

	return Packet(b.Bytes())
}

func decode[K tftpstruct](p Packet) K {
	reader := bytes.NewReader(p)
	dec := gob.NewDecoder(reader)
	var s K
	err := dec.Decode(&s)

	if err != nil {
		panic("Failed to decode packet")
	}

	return s
}

func (r *RRQPacket) Packet() Packet {
	return encode(r)
}

type WRQPacket struct {
	Type     HeaderId
	Filename string
	Eos      uint8
}

func (w *WRQPacket) Packet() Packet {
	return encode(w)
}

type DATPacket struct {
	Type  HeaderId
	Block uint32
	Size  uint32
	Data  []byte
}

func (w *DATPacket) Packet() Packet {
	return encode(w)
}

type ACKPacket struct {
	Type  HeaderId
	Block uint32
}

func (a *ACKPacket) Packet() Packet {
	return encode(a)
}

type ERRPacket struct {
	Type      HeaderId
	Errstring string
	Eos       uint8
}

func (e *ERRPacket) Packet() Packet {
	return encode(e)
}

// Type reads the type of packet from Packet.
// The most significant bit of a packet is at the first,
// so we must read the first two bytes.
// CreateRRQ creates an RRQPacket from a generic Packet.

func NewRRQ(p Packet) *RRQPacket {
	r := decode[RRQPacket](p)
	return &r
}

func NewWRQ(p Packet) *WRQPacket {
	w := decode[WRQPacket](p)
	return &w
}

func NewDAT(p Packet) *DATPacket {
	d := decode[DATPacket](p)
	return &d
}

func NewACK(p Packet) *ACKPacket {
	a := decode[ACKPacket](p)
	return &a
}

func NewERR(p Packet) *ERRPacket {
	e := decode[ERRPacket](p)
	return &e
}
