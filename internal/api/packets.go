package api

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

// GossipAnnounce
// From client to server, ...
type GossipAnnounce struct {
	PacketHeader
	TTL uint8
	/* reserved, 8 bits */
	DataType uint16
	Data     []byte
}

// GossipNotify
// From client to server, ...
type GossipNotify struct {
	PacketHeader
	/* reserved, 16 bits */
	DataType uint16
}

// GossipNotification
// From server to client, ...
type GossipNotification struct {
	PacketHeader
	MessageID uint16
	DataType  uint16
	Data      []byte
}

// GossipValidation
// From client to server, ...
type GossipValidation struct {
	PacketHeader
	MessageID uint16
	/* reserved, 15 bits */
	IsValid bool
}

func NewGossipNotification(messageID uint16, dataType uint16, data []byte) (*GossipNotification, error) {
	size := 6 + len(data)
	if size > 65535 {
		return nil, ErrCreatePacketSizeExceeded
	}
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
