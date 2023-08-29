package gossip

import "encoding/binary"

// WriteablePacket represents a packet struct that can be converted to a slice of bytes.
type WritablePacket interface {
	ToBytes() []byte
}

// ToBytes converts the Node struct to a slice of bytes.
// The Node object takes the form of <Identity>\t<Address>\n
func (n *Node) ToBytes() []byte {
	var bytes []byte
	bytes = append(bytes, n.Identity...)
	bytes = append(bytes, []byte("\t")...)
	bytes = append(bytes, []byte(n.Address)...)
	bytes = append(bytes, []byte("\n")...)
	return bytes
}

// ToBytes converts the PacketHeader struct to a slice of bytes.
func (p *PacketHeader) ToBytes() []byte {
	var bytes []byte
	bytes = binary.BigEndian.AppendUint16(bytes, p.Size)
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(p.Type))
	bytes = append(bytes, p.SenderIdentity...)
	return bytes
}

// ToBytes converts the PacketFooter struct to a slice of bytes.
func (p *PacketFooter) ToBytes() []byte {
	var bytes []byte
	bytes = append(bytes, p.Signature...)
	return bytes
}

// ToBytes converts the PacketPing struct to a slice of bytes.
func (p *PacketPing) ToBytes() []byte {
	var bytes []byte
	bytes = append(bytes, p.PacketHeader.ToBytes()...)
	bytes = append(bytes, p.PacketFooter.ToBytes()...)
	return bytes
}

// ToBytes converts the PacketPong struct to a slice of bytes.
func (p *PacketPong) ToBytes() []byte {
	var bytes []byte
	bytes = append(bytes, p.PacketHeader.ToBytes()...)
	bytes = append(bytes, p.PacketFooter.ToBytes()...)
	return bytes
}

// ToBytes converts the PacketPullRequest struct to a slice of bytes.
func (p *PacketPullRequest) ToBytes() []byte {
	var bytes []byte
	bytes = append(bytes, p.PacketHeader.ToBytes()...)
	bytes = append(bytes, p.PacketFooter.ToBytes()...)
	return bytes
}

// ToBytes converts the PacketPullResponse struct to a slice of bytes.
func (p *PacketPullResponse) ToBytes() []byte {
	var bytes []byte
	bytes = append(bytes, p.PacketHeader.ToBytes()...)
	for _, node := range p.Nodes {
		bytes = append(bytes, node.ToBytes()...)
	}
	bytes = append(bytes, p.PacketFooter.ToBytes()...)
	return bytes
}

// ToBytes converts the PacketPushRequest struct to a slice of bytes.
func (p *PacketPushRequest) ToBytes() []byte {
	var bytes []byte
	bytes = append(bytes, p.PacketHeader.ToBytes()...)
	bytes = append(bytes, p.PacketFooter.ToBytes()...)
	return bytes
}

// ToBytes converts the PacketPushChallenge struct to a slice of bytes.
func (p *PacketPushChallenge) ToBytes() []byte {
	var bytes []byte
	bytes = append(bytes, p.PacketHeader.ToBytes()...)
	bytes = binary.BigEndian.AppendUint32(bytes, p.Difficulty)
	bytes = append(bytes, p.Challenge...)
	bytes = append(bytes, p.PacketFooter.ToBytes()...)
	return bytes
}

// ToBytes converts the PacketPush struct to a slice of bytes.
func (p *PacketPush) ToBytes() []byte {
	var bytes []byte
	bytes = append(bytes, p.PacketHeader.ToBytes()...)
	bytes = append(bytes, p.Challenge...)
	bytes = append(bytes, p.Nonce...)
	bytes = append(bytes, p.Node.ToBytes()...)
	bytes = append(bytes, p.PacketFooter.ToBytes()...)
	return bytes
}

// ToBytes converts the PacketMessage struct to a slice of bytes.
func (p *PacketMessage) ToBytes() []byte {
	var bytes []byte
	bytes = append(bytes, p.PacketHeader.ToBytes()...)
	bytes = append(bytes, byte(p.TTL))
	// Appending 0x00 as the reserved byte.
	bytes = append(bytes, byte(0x00))
	bytes = binary.BigEndian.AppendUint16(bytes, p.DataType)
	bytes = append(bytes, p.Data...)
	bytes = append(bytes, p.PacketFooter.ToBytes()...)
	return bytes
}
