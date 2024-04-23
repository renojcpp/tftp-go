package tftp

import (
	"errors"
	"fmt"
)

func HandleDAT(p Packet, ackwant uint32) (bool, error) {
	dat := DATPacket(p)
	done := false
	if len(dat.Data()) > 512 {
		return false, errors.New("too many bytes of data on DAT Packet")
	}

	if dat.Size() != uint32(len(dat.Data())) {
		return false, errors.New("Size header reporting incorrect ")
	}

	if len(dat.Data()) < 512 {
		done = true
	}

	if dat.Block() != ackwant {
		return false, fmt.Errorf("Unexpected block data %d", ackwant)
	}

	return done, nil
}
