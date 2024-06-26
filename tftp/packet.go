package tftp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
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
type RRQPacket Packet

func (rrq *RRQPacket) Filename() string {
	var ss strings.Builder
	binary.Write(&ss, binary.BigEndian, (*rrq)[2:])
	filename := strings.TrimRight(ss.String(), "\x00")
	return filename
}

type WRQPacket Packet

func (wrq *WRQPacket) Filename() string {
	cast := (*RRQPacket)(wrq)

	return cast.Filename()
}

type DATPacket Packet

func (dat *DATPacket) Block() uint32 {
	n := binary.BigEndian.Uint32((*dat)[2:6])
	return n
}

func (dat *DATPacket) Size() uint32 {
	n := binary.BigEndian.Uint32((*dat)[6:10])

	return n
}

func (dat *DATPacket) Data() []byte {
	return (*dat)[10:]
}

type ACKPacket Packet

func (ack *ACKPacket) Block() uint32 {
	n := binary.BigEndian.Uint32((*ack)[2:])

	return n
}

type ERRPacket Packet

func (errp *ERRPacket) Errstring() string {
	var ss strings.Builder
	binary.Write(&ss, binary.BigEndian, (*errp)[2:])

	return ss.String()
}

func (p Packet) Type() HeaderId {
	n := binary.BigEndian.Uint16(p[0:2])

	return HeaderId(n)
}

func Encode(fields []interface{}) Packet {
	buf := new(bytes.Buffer)

	for _, v := range fields {
		switch val := v.(type) {
		case string:
			encodedString := append([]byte(val), 0)
			buf.Write(encodedString)
		default:
			err := binary.Write(buf, binary.BigEndian, v)
			if err != nil {
				fmt.Println(err)
				panic("failed to write value")
			}
		}
	}

	return buf.Bytes()
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

func EncodeErr(s string) Packet {
	d := []any{
		ERR,
		s,
		EOS,
	}

	return Encode(d)
}
