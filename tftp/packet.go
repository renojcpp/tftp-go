package tftp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type HeaderId uint16

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

type Packet []byte

type RRQPacket struct {
	Filename string
}

type WRQPacket struct {
	Filename string
}

type DATPacket struct {
	Block uint32
	Size  uint32
	Data  []byte
}

type ACKPacket struct {
	Block uint32
}

type ERRPacket struct {
	Errstring string
}

// Type reads the type of packet from Packet.
// The most significant bit of a packet is at the first,
// so we must read the first two bytes.
func (p Packet) Type() HeaderId {
	reader := bytes.NewReader(p[0:2])
	var h HeaderId
	err := binary.Read(reader, binary.BigEndian, &h)

	if err != nil {
		panic("Failed to read byte")
	}

	if h > 5 {
		panic(fmt.Sprintf("Unknown type: %d", h))
	}

	return HeaderId(h)
}

// CreateRRQ creates an RRQPacket from a generic Packet.
func CreateRRQ(p Packet) RRQPacket {
	sl := p[2 : len(p)-1]
	reader := bytes.NewReader(sl)

	var name string

	err := binary.Read(reader, binary.BigEndian, &name)

	if err != nil {
		panic("Failed to create RRQ packet")
	}

	return RRQPacket{
		name,
	}

}

func CreateWRQ(p Packet) WRQPacket {
	sl := p[2 : len(p)-1]
	reader := bytes.NewReader(sl)

	var name string

	err := binary.Read(reader, binary.BigEndian, &name)

	if err != nil {
		panic("Failed to create WRQ packet")
	}

	return WRQPacket{
		name,
	}
}

func CreateDAT(p Packet) DATPacket {
	sl := p[2:]
	reader := bytes.NewReader(sl)

	var dat DATPacket
	err := binary.Read(reader, binary.BigEndian, &dat)

	if err != nil {
		panic("Failed to create DAT packet")
	}

	return dat
}

func CreateACK(p Packet) ACKPacket {
	sl := p[2:]
	reader := bytes.NewReader(sl)

	var block uint32

	err := binary.Read(reader, binary.BigEndian, &block)
	if err != nil {
		panic("Failed to create ACK packet")
	}

	return ACKPacket{block}
}

func CreateERR(p Packet) ERRPacket {
	sl := p[2:]
	reader := bytes.NewReader(sl)

	var errstring string
	err := binary.Read(reader, binary.BigEndian, &errstring)

	if err != nil {
		panic("Failed to create ERR packet")
	}

	return ERRPacket{errstring}
}
