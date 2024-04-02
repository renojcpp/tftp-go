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

func (rrq *RRQPacket) Filename() string {
	return string((*rrq)[2 : len(*rrq)-1])
}

type WRQPacket Packet

func (wrq *WRQPacket) Filename() string {
	cast := (*RRQPacket)(wrq)

	return cast.Filename()
}

type DATPacket Packet

func (dat *DATPacket) Block() uint32 {
	n, _ := binary.Uvarint((*dat)[2:6])

	return uint32(n)
}

func (dat *DATPacket) Size() uint32 {
	n, _ := binary.Uvarint((*dat)[6:10])

	return uint32(n)
}

func (dat *DATPacket) Data() []byte {
	return (*dat)[10:]
}

type ACKPacket Packet

func (ack *ACKPacket) Block() uint32 {
	n, _ := binary.Uvarint((*ack)[2:])

	return uint32(n)
}

type ERRPacket Packet

func (errp *ERRPacket) Errstring() string {
	return string((*errp)[2:])
}

func (p Packet) Type() HeaderId {
	n, _ := binary.Uvarint(p[0:2])
	return HeaderId(n)
}

func Encode(fields []any) Packet {
	buf := new(bytes.Buffer)

	for _, v := range fields {
		err := binary.Write(buf, binary.BigEndian, v)
		if err != nil {
			panic("failed to create ack packet")
		}
	}

	return buf.Bytes()
}

func Decode[k ~[]byte](p k) (Packet, error) {
	reader := bytes.NewReader(p)
	buf := make([]byte, len(p))

	err := binary.Read(reader, binary.BigEndian, p)

	if err != nil {
		return nil, err
	}

	return buf, nil
}

func EncodeRRQ(s string) Packet {
	d := []any{
		RRQ,
		s,
		EOS,
	}
	return Encode(d)
}

func EncodeWRQ(s string) Packet {
	d := []any{
		WRQ,
		s,
		EOS,
	}

	return Encode(d)

}

func EncodeDAT(b, s uint32, data []byte) Packet {
	d := []any{
		DAT,
		b,
		s,
		data,
	}

	return Encode(d)
}

func EncodeACK(b uint32) Packet {
	d := []any{
		ACK,
		b,
	}

	return Encode(d)
}

func EncodeWRR(s string) Packet {
	d := []any{
		ERR,
		s,
		EOS,
	}

	return Encode(d)
}
