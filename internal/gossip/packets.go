package gossip

import "errors"

type MessageType uint16

const (
	MessageTypeGossipPing MessageType = 0x0030
	MessageTypeGossipPong MessageType = 0x0031

	MessageTypeGossipPullRequest  MessageType = 0x0040
	MessageTypeGossipPullResponse MessageType = 0x0041

	MessageTypeGossipPushRequest   MessageType = 0x0050
	MessageTypeGossipPushChallenge MessageType = 0x0051
	MessageTypeGossipPush          MessageType = 0x0052

	MessageTypeGossipMessage MessageType = 0x0060

	// PacketHeaderSize represents the size of the PacketHeader in bytes.
	PacketHeaderSize uint16 = 4
)

var (
	ErrCreatePacketSizeExceeded = errors.New("packet could not be created, maximum size exceeded")
)

// PacketHeader represents the header component of each packet.
type PacketHeader struct {
	Size uint16
	Type MessageType
}

// PacketPing represents a probe sent from one node, n1, to the other node, n2, to check if n2 is still alive.
type PacketPing PacketHeader

// PacketPong represents a reply to the ping indicating that n2 is alive.
type PacketPong PacketHeader

// PacketPullRequest represents a request to a node to share its view.
type PacketPullRequest PacketHeader

// PacketPullResponse represents the nodes requested from the pull request.
type PacketPullResponse struct {
	PacketHeader
	Nodes []byte
}

// PacketPushRequest represents the request of a node, n1, to send its ID to another node, n2.
type PacketPushRequest PacketHeader

// PacketPushChallenge represents the response to the push request with an included POW challenge.
type PacketPushChallenge struct {
	PacketHeader
	Difficulty uint32
	Challenge  []byte
}

// PacketPush represents a reply to the challenge with the correct nonce and node.
type PacketPush struct {
	PacketHeader
	Challenge []byte
	Nonce     []byte
	Node      string
}

// PacketMessage represents the gossip message to be spread amongst all nodes within the local view when received from a known peer. TTL should be decreased every time the message is forwarded with a TTL=1 not being forwarded any further.
type PacketMessage struct {
	PacketHeader
	TTL uint8
	/* reserved 8 bits */
	DataType uint16
	Data     []byte
}
