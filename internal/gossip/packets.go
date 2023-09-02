package gossip

import (
	"errors"
	challengeModule "gossiphers/internal/challenge"
)

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

	// PacketHeaderSize represents the length of the PacketHeader in bytes.
	// 2 bytes for the size field, 2 bytes for the Message Type, and 32 bytes for the Sender Identity.
	PacketHeaderSize int = 36
	// SignatureSize represents the length of the signature in bytes.
	SignatureSize    int = 64
	PeerIdentitySize int = 32

	MaxPacketSize = 65535
)

var (
	ErrCreatePacketInvalidComponentSize = errors.New("packet could not be created, component of invalid size or maximum size exceeded")
)

// PacketHeader represents the header component of each packet.
type PacketHeader struct {
	Size           uint16      // 2
	Type           MessageType // 2
	SenderIdentity []byte      // 32
}

// PacketFooter represents the footer component of each packet
type PacketFooter struct {
	Signature []byte // 64
}

// PacketPing represents a probe sent from one node, n1, to the other node, n2, to check if n2 is still alive.
type PacketPing struct {
	PacketHeader
	PacketFooter
}

func NewPacketPing(senderID []byte) (*PacketPing, error) {
	if len(senderID) != PeerIdentitySize {
		return nil, ErrCreatePacketInvalidComponentSize
	}
	return &PacketPing{
		PacketHeader: PacketHeader{
			Size:           uint16(PacketHeaderSize + SignatureSize),
			Type:           MessageTypeGossipPing,
			SenderIdentity: senderID,
		},
		PacketFooter: PacketFooter{
			Signature: nil,
		},
	}, nil
}

// PacketPong represents a reply to the ping indicating that n2 is alive.
type PacketPong struct {
	PacketHeader
	PacketFooter
}

func NewPacketPong(senderID []byte) (*PacketPing, error) {
	if len(senderID) != PeerIdentitySize {
		return nil, ErrCreatePacketInvalidComponentSize
	}
	return &PacketPing{
		PacketHeader: PacketHeader{
			Size:           uint16(PacketHeaderSize + SignatureSize),
			Type:           MessageTypeGossipPong,
			SenderIdentity: senderID,
		},
		PacketFooter: PacketFooter{
			Signature: nil,
		},
	}, nil
}

// PacketPullRequest represents a request to a node to share its view.
type PacketPullRequest struct {
	PacketHeader
	PacketFooter
}

func NewPacketPullRequest(senderID []byte) (*PacketPullRequest, error) {
	if len(senderID) != PeerIdentitySize {
		return nil, ErrCreatePacketInvalidComponentSize
	}
	return &PacketPullRequest{
		PacketHeader: PacketHeader{
			Size:           uint16(PacketHeaderSize + SignatureSize),
			Type:           MessageTypeGossipPullRequest,
			SenderIdentity: senderID,
		},
		PacketFooter: PacketFooter{
			Signature: nil,
		},
	}, nil
}

// PacketPullResponse represents the nodes requested from the pull request.
type PacketPullResponse struct {
	PacketHeader
	Nodes []Node
	PacketFooter
}

func NewPacketPullResponse(senderID []byte, nodes []Node) (*PacketPullResponse, error) {
	packetSize := PacketHeaderSize + SignatureSize
	for _, node := range nodes {
		packetSize += len(node.ToBytes())
	}
	if len(senderID) != PeerIdentitySize || packetSize > MaxPacketSize {
		return nil, ErrCreatePacketInvalidComponentSize
	}
	return &PacketPullResponse{
		PacketHeader: PacketHeader{
			Size:           uint16(packetSize),
			Type:           MessageTypeGossipMessage,
			SenderIdentity: senderID,
		},
		Nodes: nodes,
		PacketFooter: PacketFooter{
			Signature: nil,
		},
	}, nil
}

// PacketPushRequest represents the request of a node, n1, to send its ID to another node, n2.
type PacketPushRequest struct {
	PacketHeader
	PacketFooter
}

func NewPacketPushRequest(senderID []byte) (*PacketPushRequest, error) {
	if len(senderID) != PeerIdentitySize {
		return nil, ErrCreatePacketInvalidComponentSize
	}
	return &PacketPushRequest{
		PacketHeader: PacketHeader{
			Size:           uint16(PacketHeaderSize + SignatureSize),
			Type:           MessageTypeGossipPushRequest,
			SenderIdentity: senderID,
		},
		PacketFooter: PacketFooter{
			Signature: nil,
		},
	}, nil
}

// PacketPushChallenge represents the response to the push request with an included POW challenge.
type PacketPushChallenge struct {
	PacketHeader
	Difficulty uint32
	Challenge  []byte
	PacketFooter
}

func NewPacketPushChallenge(senderID []byte, difficulty uint32, challenge []byte) (*PacketPushChallenge, error) {
	if len(senderID) != PeerIdentitySize || len(challenge) != challengeModule.ChallengeSize {
		return nil, ErrCreatePacketInvalidComponentSize
	}
	return &PacketPushChallenge{
		PacketHeader: PacketHeader{
			Size:           uint16(PacketHeaderSize+SignatureSize+challengeModule.ChallengeSize) + 4, // difficulty = 4
			Type:           MessageTypeGossipPushChallenge,
			SenderIdentity: senderID,
		},
		Difficulty: difficulty,
		Challenge:  challenge,
		PacketFooter: PacketFooter{
			Signature: nil,
		},
	}, nil
}

// PacketPush represents a reply to the challenge with the correct nonce and node.
type PacketPush struct {
	PacketHeader
	Challenge []byte
	Nonce     []byte
	Node      Node
	PacketFooter
}

func NewPacketPush(senderID []byte, challenge []byte, nonce []byte, node Node) (*PacketPush, error) {
	packetSize := PacketHeaderSize + SignatureSize + challengeModule.ChallengeSize + challengeModule.NonceSize + len(node.ToBytes())
	if len(senderID) != PeerIdentitySize || len(challenge) != challengeModule.ChallengeSize || len(nonce) != challengeModule.NonceSize || packetSize > MaxPacketSize {
		return nil, ErrCreatePacketInvalidComponentSize
	}
	return &PacketPush{
		PacketHeader: PacketHeader{
			Size:           uint16(packetSize),
			Type:           MessageTypeGossipPush,
			SenderIdentity: senderID,
		},
		Challenge: challenge,
		Nonce:     nonce,
		Node:      node,
		PacketFooter: PacketFooter{
			Signature: nil,
		},
	}, nil
}

// PacketMessage represents the gossip message to be spread amongst all nodes within the local view when received from a known peer. TTL should be decreased every time the message is forwarded with a TTL=1 not being forwarded any further.
type PacketMessage struct {
	PacketHeader
	TTL uint8
	/* reserved 8 bits */
	DataType uint16
	Data     []byte
	PacketFooter
}

func NewPacketMessage(senderID []byte, ttl uint8, dataType uint16, data []byte) (*PacketMessage, error) {
	packetSize := PacketHeaderSize + SignatureSize + 1 + 1 + 2 + len(data) // ttl = 1, reserved = 1, dataType = 2
	if len(senderID) != PeerIdentitySize || packetSize > MaxPacketSize {
		return nil, ErrCreatePacketInvalidComponentSize
	}
	return &PacketMessage{
		PacketHeader: PacketHeader{
			Size:           uint16(packetSize),
			Type:           MessageTypeGossipMessage,
			SenderIdentity: senderID,
		},
		TTL:      ttl,
		DataType: dataType,
		Data:     data,
		PacketFooter: PacketFooter{
			Signature: nil,
		},
	}, nil
}
