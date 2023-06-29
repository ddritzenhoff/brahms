package gossip

import "encoding/binary"

// WriteablePacket represents a packet struct that can be converted to a slice of bytes.
type WritablePacket interface {
	ToBytes() []byte
}

// ToBytes converts the PacketPong struct to a slice of bytes.
func (p *PacketPong) ToBytes() []byte {
	var bytes []byte
	bytes = binary.BigEndian.AppendUint16(bytes, p.Size)
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(p.Type))
	return bytes
}

// ToBytes converts the PacketPullResponse struct to a slice of bytes.
func (p *PacketPullResponse) ToBytes() []byte {
	var bytes []byte
	bytes = binary.BigEndian.AppendUint16(bytes, p.Size)
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(p.Type))
	bytes = append(bytes, p.Nodes...)
	return bytes
}

// ToBytes converts the PacketPushChallenge struct to a slice of bytes.
func (p *PacketPushChallenge) ToBytes() []byte {
	var bytes []byte
	bytes = binary.BigEndian.AppendUint16(bytes, p.Size)
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(p.Type))
	bytes = binary.BigEndian.AppendUint32(bytes, p.Difficulty)
	bytes = append(bytes, p.Challenge...)
	return bytes
}

// ToBytes converts the PacketPush struct to a slice of bytes.
func (p *PacketPush) ToBytes() []byte {
	var bytes []byte
	bytes = binary.BigEndian.AppendUint16(bytes, p.Size)
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(p.Type))
	bytes = append(bytes, p.Challenge...)
	bytes = append(bytes, p.Nonce...)
	bytes = append(bytes, []byte(p.Node)...)
	return bytes
}
