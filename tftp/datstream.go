package tftp

import "io"

// DATStream creates a stream of DATPackets
type DATStream struct {
	r     io.Reader
	block uint32
}

func (d *DATStream) Next() (DATPacket, error) {
	// read at most 511 bytes at a time,
	// we don't read 512 because the last byte
	// needs to be the EOS or null byte
	buf := make([]byte, 512)
	n, err := d.r.Read(buf)

	if err != nil {
		if err == io.EOF{
			dat :=  EncodeDAT(d.block, uint32(0), buf[:0])
			d.block += 1
			return DATPacket(dat), nil
		}else{
			return nil, err
		}
	}

	dat := EncodeDAT(d.block, uint32(len(buf[:n])), buf[:n])

	d.block += 1
	return DATPacket(dat), nil
}

func NewDATStream(r io.Reader) *DATStream {
	return &DATStream{
		r,
		1,
	}
}
