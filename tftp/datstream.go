package tftp

// DATStream creates a stream of DATPackets
type DATStream struct {
	src   []byte
	block uint32
	ptr   int
}

func (d *DATStream) Next() (DATPacket, error) {
	// read at most 512 bytes at a time
	end := min(len(d.src)-d.ptr, d.ptr+512)
	slice := d.src[d.ptr:end]

	dat, err := NewDATPacket(d.block, uint32(len(slice)), slice)
	if err != nil {
		return nil, err
	}

	d.block += 1
	d.ptr = end
	return dat, nil
}

func NewDATStream(src []byte) *DATStream {
	return &DATStream{
		src,
		1,
		0,
	}
}
