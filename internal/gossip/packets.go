package gossip

import "errors"

type MessageType uint16

const (
	MessageTypeGossipAnnounce     MessageType = 500
	MessageTypeGossipNotify       MessageType = 501
	MessageTypeGossipNotification MessageType = 502
	MessageTypeGossipValidation   MessageType = 503
)

var (
	ErrCreatePacketSizeExceeded = errors.New("packet could not be created, maximum size exceeded")
)

type PacketHeader struct {
	Size uint16
	Type MessageType
}

type PacketPing PacketHeader
type PacketPong PacketHeader

type PacketPullRequest PacketHeader
type PacketPullResponse struct {
	PacketHeader
	Nodes []byte
}

type PacketPushRequest PacketHeader
type PacketPushChallenge struct {
	PacketHeader
	Challenge []byte
}
type PacketPush struct {
	PacketHeader
	Challenge []byte
	Nonce     []byte
	Nodes     []byte
}

type PacketMessage struct {
	PacketHeader
	TTL uint8
	/* reserved 8 bits */
	DataType uint16
	Data     []byte
}
