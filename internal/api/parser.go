package api

import (
	"bufio"
	"encoding/binary"
	"errors"
)

var (
	ErrParsePacketHeaderInvalidSize = errors.New("packet header could not be parsed, header size invalid")
	ErrParsePacketHeaderInvalidType = errors.New("packet could not be parsed, type not implemented")
	ErrParsePacketInvalidSize       = errors.New("packet could not be parsed, size in header does not match received data")

	supportedIncomingMessageTypes = []MessageType{MessageTypeGossipAnnounce, MessageTypeGossipNotify, MessageTypeGossipValidation}
)

type ParseablePacket interface {
	Parse(header *PacketHeader, reader *bufio.Reader) error
}

func ParsePacketHeader(data []byte) (*PacketHeader, error) {
	if len(data) != 4 {
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

func (p *GossipAnnounce) Parse(header *PacketHeader, reader *bufio.Reader) error {
	if _, err := reader.Peek(8); err != nil {
		return ErrParsePacketInvalidSize
	}

	// discard header, already parsed
	_, err := reader.Discard(4)
	if err != nil {
		return err
	}
	p.PacketHeader = *header

	err = binary.Read(reader, binary.BigEndian, &p.TTL)
	if err != nil {
		return err
	}

	// discard reserved byte
	_, err = reader.Discard(1)
	if err != nil {
		return err
	}

	err = binary.Read(reader, binary.BigEndian, &p.DataType)
	if err != nil {
		return err
	}

	// Read data bytes, limited to the given size minus the already read bytes
	p.Data = make([]byte, header.Size-8)
	n, err := reader.Read(p.Data)
	if err != nil {
		return err
	}
	if n != int(header.Size-8) {
		return ErrParsePacketInvalidSize
	}

	// Any leftover bytes are larger than specified in the header
	if _, err := reader.Peek(1); err == nil {
		return ErrParsePacketInvalidSize
	}
	return nil
}

func (p *GossipNotify) Parse(header *PacketHeader, reader *bufio.Reader) error {
	if _, err := reader.Peek(8); err != nil || header.Size != 8 {
		return ErrParsePacketInvalidSize
	}

	// discard header, already parsed
	_, err := reader.Discard(4)
	if err != nil {
		return err
	}
	p.PacketHeader = *header

	// discard reserved bytes
	_, err = reader.Discard(2)
	if err != nil {
		return err
	}

	err = binary.Read(reader, binary.BigEndian, &p.DataType)
	if err != nil {
		return err
	}

	// Any leftover bytes are larger than specified in the header
	if _, err := reader.Peek(1); err == nil {
		return ErrParsePacketInvalidSize
	}
	return nil
}

func (p *GossipValidation) Parse(header *PacketHeader, reader *bufio.Reader) error {
	if _, err := reader.Peek(8); err != nil || header.Size != 8 {
		return ErrParsePacketInvalidSize
	}

	// discard header, already parsed
	_, err := reader.Discard(4)
	if err != nil {
		return err
	}
	p.PacketHeader = *header

	err = binary.Read(reader, binary.BigEndian, &p.MessageID)
	if err != nil {
		return err
	}

	// discard reserved byte
	_, err = reader.Discard(1)
	if err != nil {
		return err
	}

	// we can only read full bytes, the last bit contains our isValid flag
	lastByte, err := reader.ReadByte()
	if err != nil {
		return err
	}

	p.IsValid = lastByte&1 == 1

	// Any leftover bytes are larger than specified in the header
	if _, err := reader.Peek(1); err == nil {
		return ErrParsePacketInvalidSize
	}
	return nil
}
