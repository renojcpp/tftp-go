package tftp

// DATStream creates a stream of DATPackets
type DATStream struct {
	src   []byte
	block uint32
	ptr   int
}

func (d *DATStream) Next() DATPacket {
	// read at most 512 bytes at a time
	end := min(len(d.src)-d.ptr, d.ptr+512)
	slice := d.src[d.ptr:end]

	dat := EncodeDAT(d.block, uint32(len(slice)), slice)

	d.block += 1
	d.ptr = end
	return DATPacket(dat)
}

func NewDATStream(src []byte) *DATStream {
	return &DATStream{
		src,
		1,
		0,
	}
}
