package api

import (
	"encoding/binary"
)

type WritablePacket interface {
	ToBytes() []byte
}

func (p *GossipNotification) ToBytes() []byte {
	var bytes []byte
	bytes = binary.BigEndian.AppendUint16(bytes, p.Size)
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(p.Type))
	bytes = binary.BigEndian.AppendUint16(bytes, p.MessageID)
	bytes = binary.BigEndian.AppendUint16(bytes, p.DataType)
	bytes = append(bytes, p.Data...)

	return bytes
}
