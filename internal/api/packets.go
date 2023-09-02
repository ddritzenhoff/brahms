package api

import "errors"

// MessageType represents the different types of messages existing within the API specification.
type MessageType uint16

const (
	MessageTypeGossipAnnounce     MessageType = 500
	MessageTypeGossipNotify       MessageType = 501
	MessageTypeGossipNotification MessageType = 502
	MessageTypeGossipValidation   MessageType = 503
)

var (
	ErrCreatePacketSizeExceeded         = errors.New("packet could not be created, maximum size exceeded")
	consecutiveOutgoingMessageID uint16 = 0
)

// PacketHeader represents the header component of each packet.
type PacketHeader struct {
	Size uint16
	Type MessageType
}

// GossipAnnounce
// From client to server, requests the local peer to distribute the given message using the Gossip implementation
type GossipAnnounce struct {
	PacketHeader
	TTL uint8
	/* reserved, 8 bits */
	DataType uint16
	Data     []byte
}

// GossipNotify
// From client to server, registers the sending client to receive GossipNotification packets
// when a Gossip message of a certain type is received by the local peer
type GossipNotify struct {
	PacketHeader
	/* reserved, 16 bits */
	DataType uint16
}

// GossipNotification
// From server to client, passes a received Gossip message to registered client
type GossipNotification struct {
	PacketHeader
	MessageID uint16
	DataType  uint16
	Data      []byte
}

// GossipValidation
// From client to server, confirms the validity of the data in a received GossipNotification
type GossipValidation struct {
	PacketHeader
	MessageID uint16
	/* reserved, 15 bits */
	IsValid bool
}

// NewGossipNotification creates a new Gossip Notification packet.
func NewGossipNotification(dataType uint16, data []byte) (*GossipNotification, error) {
	size := 8 + len(data) // 4B PacketHeader + 2B MessageID + 2B DataType
	if size > 65535 {
		return nil, ErrCreatePacketSizeExceeded
	}
	messageID := consecutiveOutgoingMessageID
	consecutiveOutgoingMessageID++
	return &GossipNotification{
		PacketHeader: PacketHeader{
			Size: uint16(size),
			Type: MessageTypeGossipNotification,
		},
		MessageID: messageID,
		DataType:  dataType,
		Data:      data,
	}, nil
}
