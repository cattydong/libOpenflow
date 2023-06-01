package protocol

import (
	"antrea.io/libOpenflow/util"
	"encoding/binary"
	"errors"
)

type TCP struct {
	PortSrc uint16
	PortDst uint16
	SeqNum  uint32
	AckNum  uint32

	HdrLen uint8
	Code   uint8

	WinSize  uint16
	Checksum uint16
	UrgFlag  uint16
	Options  util.Buffer

	Data []byte
}

func NewTCP() *TCP {
	u := new(TCP)
	u.Options = *new(util.Buffer)
	u.Data = make([]byte, 0)
	return u
}

func (t *TCP) Len() (n uint16) {
	if t.HdrLen < 5 {
		t.HdrLen = 5
	}
	length := uint16(4 * t.HdrLen)
	if t.Data != nil {
		return length + uint16(len(t.Data))
	}
	return length
}

func (t *TCP) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(t.Len()))
	binary.BigEndian.PutUint16(data[:2], t.PortSrc)
	binary.BigEndian.PutUint16(data[2:4], t.PortDst)
	binary.BigEndian.PutUint32(data[4:8], t.SeqNum)
	binary.BigEndian.PutUint32(data[8:12], t.AckNum)

	data[12] = (t.HdrLten << 4) & 0xf0
	data[13] = t.Code & 0x3f

	binary.BigEndian.PutUint16(data[14:16], t.WinSize)
	binary.BigEndian.PutUint16(data[16:18], t.Checksum)
	binary.BigEndian.PutUint16(data[18:20], t.UrgFlag)

	n := 20
	var b []byte
	if b, err = t.Options.MarshalBinary(); err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)

	copy(data[n:], t.Data)

	return
}

func (t *TCP) UnmarshalBinary(data []byte) error {
	if len(data) < 20 {
		return errors.New("The []byte is too short to unmarshal a full ARP message.")
	}
	t.PortSrc = binary.BigEndian.Uint16(data[:2])
	t.PortDst = binary.BigEndian.Uint16(data[2:4])
	t.SeqNum = binary.BigEndian.Uint32(data[4:8])
	t.AckNum = binary.BigEndian.Uint32(data[8:12])

	t.HdrLen = (data[12] >> 4) & 0xf
	t.Code = data[13] & 0x3f

	t.WinSize = binary.BigEndian.Uint16(data[14:16])
	t.Checksum = binary.BigEndian.Uint16(data[16:18])
	t.UrgFlag = binary.BigEndian.Uint16(data[18:20])

	n := 20
	if t.HdrLen*4 > 20 {
		t.Options = *new(util.Buffer)
		err := t.Options.UnmarshalBinary(data[n:int(t.HdrLen*4)])
		if err != nil {
			return err
		}
		n += int(t.HdrLen*4) - n
	}

	if len(data) > n {
		t.Data = make([]byte, (len(data) - int(t.HdrLen*4)))
		copy(t.Data, data[n:])
	}

	return nil
}
