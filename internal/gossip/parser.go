package gossip

import (
	"bufio"
	"encoding/binary"
	"errors"
	"gossiphers/internal/challenge"
	"io"
)

var (
	ErrParsePacketHeaderInvalidSize = errors.New("packet header could not be parsed, header size invalid")
	ErrParsePacketHeaderInvalidType = errors.New("packet could not be parsed, type not implemented")
	ErrParsePacketInvalidSize       = errors.New("packet could not be parsed, size in header does not match received data")

	supportedIncomingMessageTypes = []MessageType{MessageTypeGossipPing, MessageTypeGossipPong, MessageTypeGossipPullRequest, MessageTypeGossipPullResponse, MessageTypeGossipPush, MessageTypeGossipPushChallenge, MessageTypeGossipPushRequest, MessageTypeGossipMessage}
)

// ParseablePacket represents the ability to parse this particular packet.
type ParseablePacket interface {
	Parse(header *PacketHeader, reader *bufio.Reader) error
}

// ParsePacketHeader parses the header from all of the P2P packets, which is always the same.
// Returns ErrParsePacketHeaderInvalidSize if the header isn't of size PacketHeaderSize.
// Returns ErrParsePacketHeaderInvalidType if the packet type is not supported.
func ParsePacketHeader(data []byte) (*PacketHeader, error) {
	if len(data) != int(PacketHeaderSize) {
		return nil, ErrParsePacketHeaderInvalidSize
	}
	size := binary.BigEndian.Uint16(data[:2])
	messageType := MessageType(binary.BigEndian.Uint16(data[2:4]))

	isSupported := false
	for _, mt := range supportedIncomingMessageTypes {
		if messageType == mt {
			isSupported = true
		}
	}
	if !isSupported {
		return nil, ErrParsePacketHeaderInvalidType
	}

	return &PacketHeader{Size: size, Type: messageType}, nil
}

// Parse parses a PullResponse packet.
// Returns ErrParsePacketInvalidSize if the packet isn't the same size as specified in header.Size.
func (p *PacketPullResponse) Parse(header *PacketHeader, reader *bufio.Reader) error {
	// Discard header, already parsed.
	_, err := reader.Discard(int(PacketHeaderSize))
	if err != nil {
		return err
	}
	p.PacketHeader = *header

	data := make([]byte, header.Size-PacketHeaderSize)
	_, err = io.ReadFull(reader, data)
	if err != nil {
		return err
	}
	p.Nodes = data

	// Any leftover bytes are larger than specified in the header
	if _, err := reader.Peek(1); err == nil {
		return ErrParsePacketInvalidSize
	}

	return nil
}

// Parse parses a PushChallenge packet.
// Returns ErrParsePacketInvalidSize if the packet isn't the same size as specified in header.Size.
func (p *PacketPushChallenge) Parse(header *PacketHeader, reader *bufio.Reader) error {
	// Discard header, already parsed.
	_, err := reader.Discard(int(PacketHeaderSize))
	if err != nil {
		return err
	}
	p.PacketHeader = *header

	err = binary.Read(reader, binary.BigEndian, p.Difficulty)
	if err != nil {
		return err
	}

	data := make([]byte, challenge.ChallengeSize)
	_, err = io.ReadFull(reader, data)
	if err != nil {
		return err
	}
	p.Challenge = data

	// Any leftover bytes are larger than specified in the header
	if _, err := reader.Peek(1); err == nil {
		return ErrParsePacketInvalidSize
	}

	return nil
}

// Parse parses a Push packet.
// Returns ErrParsePacketInvalidSize if the packet isn't the same size as specified in header.Size.
func (p *PacketPush) Parse(header *PacketHeader, reader *bufio.Reader) error {
	// Discard header, already parsed.
	_, err := reader.Discard(int(PacketHeaderSize))
	if err != nil {
		return err
	}
	p.PacketHeader = *header

	ch := make([]byte, challenge.ChallengeSize)
	_, err = io.ReadFull(reader, ch)
	if err != nil {
		return err
	}
	p.Challenge = ch

	nce := make([]byte, challenge.NonceSize)
	_, err = io.ReadFull(reader, nce)
	if err != nil {
		return err
	}
	p.Nonce = nce

	nodeSize := int(header.Size) - int(PacketHeaderSize) - challenge.ChallengeSize - challenge.NonceSize
	if nodeSize <= 0 {
		return ErrParsePacketInvalidSize
	}
	data := make([]byte, nodeSize)
	_, err = io.ReadFull(reader, data)
	if err != nil {
		return err
	}
	p.Node = string(data)

	// Any leftover bytes are larger than specified in the header
	if _, err := reader.Peek(1); err == nil {
		return ErrParsePacketInvalidSize
	}

	return nil
}

// Parse parses a Push packet.
// Returns ErrParsePacketInvalidSize if the packet isn't the same size as specified in header.Size.
func (p *PacketMessage) Parse(header *PacketHeader, reader *bufio.Reader) error {
	// Discard header, already parsed.
	_, err := reader.Discard(int(PacketHeaderSize))
	if err != nil {
		return err
	}
	p.PacketHeader = *header

	err = binary.Read(reader, binary.BigEndian, p.TTL)
	if err != nil {
		return err
	}

	// Discard reserved byte.
	reader.Discard(1)

	err = binary.Read(reader, binary.BigEndian, p.DataType)
	if err != nil {
		return err
	}

	// header.Size - uint8 (TTL) - uint8 (Reserved byte) - uint16 (DataType)
	r := int(header.Size) - 1 - 1 - 2
	data := make([]byte, r)
	_, err = io.ReadFull(reader, data)
	if err != nil {
		return err
	}
	p.Data = data

	// Any leftover bytes are larger than specified in the header
	if _, err := reader.Peek(1); err == nil {
		return ErrParsePacketInvalidSize
	}

	return nil
}
