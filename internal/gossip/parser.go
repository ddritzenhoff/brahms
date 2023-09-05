package gossip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"gossiphers/internal/challenge"
	"strings"
)

var (
	ErrParsePacketHeaderInvalidSize = errors.New("packet header could not be parsed, header size invalid")
	ErrParsePacketHeaderInvalidType = errors.New("packet could not be parsed, type not implemented")
	ErrParsePacketInvalidSize       = errors.New("packet could not be parsed, size in header does not match received data")

	supportedIncomingMessageTypes = []MessageType{MessageTypeGossipPing, MessageTypeGossipPong, MessageTypeGossipPullRequest, MessageTypeGossipPullResponse, MessageTypeGossipPush, MessageTypeGossipPushChallenge, MessageTypeGossipPushRequest, MessageTypeGossipMessage}
)

// ParseablePacket represents the ability to parse this particular packet.
type ParseablePacket interface {
	Parse(header *PacketHeader, reader *bytes.Reader) error
}

// ParsePacketHeader parses the header from all of the P2P packets, which is always the same.
// Returns ErrParsePacketHeaderInvalidSize if the header isn't of size PacketHeaderSize.
// Returns ErrParsePacketHeaderInvalidType if the packet type is not supported.
func ParsePacketHeader(data []byte) (*PacketHeader, error) {
	if len(data) != PacketHeaderSize {
		return nil, ErrParsePacketHeaderInvalidSize
	}
	size := binary.BigEndian.Uint16(data[:2])
	messageType := MessageType(binary.BigEndian.Uint16(data[2:4]))
	timestamp := binary.BigEndian.Uint64(data[4:12])
	senderIdentity, err := NewIdentity(data[12 : 12+IdentitySize])
	if err != nil {
		return nil, err
	}

	isSupported := false
	for _, mt := range supportedIncomingMessageTypes {
		if messageType == mt {
			isSupported = true
		}
	}
	if !isSupported {
		return nil, ErrParsePacketHeaderInvalidType
	}

	return &PacketHeader{Size: size, Type: messageType, Timestamp: timestamp, SenderIdentity: *senderIdentity}, nil
}

// parseSignature takes tries to extract the signature from the reader.
func parseSignature(reader *bytes.Reader) ([]byte, error) {
	if reader.Len() != SignatureSize {
		return nil, fmt.Errorf("remaining bytes in the reader not equivalent to the signature length: %d bytes remaining", reader.Len())
	}
	sig := make([]byte, SignatureSize)
	n, err := reader.Read(sig)
	if err != nil {
		return nil, err
	}
	if n != SignatureSize {
		return nil, fmt.Errorf("signature improperly read: only %d bytes read", n)
	}
	return sig, nil
}

// Parse parses the Ping packet assuming that the packet has already been decrypted.
func (p *PacketPing) Parse(header *PacketHeader, reader *bytes.Reader) error {
	// Assuming the header has already been read and that the reader is now on the first byte of the data.
	sig, err := parseSignature(reader)
	if err != nil {
		return err
	}

	p.PacketHeader = *header
	p.Signature = sig

	return nil
}

// Parse parses the Pong packet assuming that the packet has already been decrypted.
func (p *PacketPong) Parse(header *PacketHeader, reader *bytes.Reader) error {
	// Assuming the header has already been read and that the reader is now on the first byte of the data.
	sig, err := parseSignature(reader)
	if err != nil {
		return err
	}

	p.PacketHeader = *header
	p.Signature = sig
	return nil
}

// Parse parses the PullRequest packet assuming that the packet has already been decrypted.
func (p *PacketPullRequest) Parse(header *PacketHeader, reader *bytes.Reader) error {
	// Assuming the header has already been read and that the reader is now on the first byte of the data.
	sig, err := parseSignature(reader)
	if err != nil {
		return err
	}

	p.PacketHeader = *header
	p.Signature = sig
	return nil
}

// parseNodes takes a string of the form <identity1>\t<address1>\n<identity2>\t<address2>\n<identity3>\t<address3>\n... and parses it into a slice of nodes.
func parseNodes(nodeBytes []byte) ([]Node, error) {
	reader := bytes.NewReader(nodeBytes)
	var nodes []Node
	for {
		if reader.Len() < IdentitySize+3 {
			break
		}
		nodeIdentity := make([]byte, IdentitySize)
		_, err := reader.Read(nodeIdentity)
		if err != nil {
			return nil, err
		}

		var rest []rune
		for {
			readRune, _, err := reader.ReadRune()
			if err != nil {
				return nil, err
			}
			if readRune == '\n' {
				break
			}
			rest = append(rest, readRune)
		}
		if !strings.HasPrefix(string(rest), "\t") {
			return nil, fmt.Errorf("expected a \\t separator in node list, found %v", rest[0])
		}
		address := strings.TrimPrefix(string(rest), "\t")
		newNode, err := NewNode(nodeIdentity, address)
		if err != nil {
			return nil, err
		}

		nodes = append(nodes, *newNode)
	}
	return nodes, nil
}

// Parse parses the PullResponse packet assuming that the packet has already been decrypted.
func (p *PacketPullResponse) Parse(header *PacketHeader, reader *bytes.Reader) error {
	// Assuming the header has already been read and that the reader is now on the first byte of the data
	nodesTotalSize := reader.Len() - SignatureSize
	if nodesTotalSize <= 0 {
		return errors.New("expecting view, but no nodes have been included within the PullResponse packet")
	}
	nodesStr := make([]byte, nodesTotalSize)
	_, err := reader.Read(nodesStr)
	if err != nil {
		return err
	}
	nodes, err := parseNodes(nodesStr)
	if err != nil {
		return err
	}

	sig, err := parseSignature(reader)
	if err != nil {
		return err
	}

	p.PacketHeader = *header
	p.Nodes = nodes
	p.Signature = sig
	return nil
}

// Parse parses the PushRequest packet assuming that the packet has already been decrypted.
func (p *PacketPushRequest) Parse(header *PacketHeader, reader *bytes.Reader) error {
	sig, err := parseSignature(reader)
	if err != nil {
		return err
	}

	p.PacketHeader = *header
	p.Signature = sig
	return nil
}

// Parse parses the PushChallenge packet assuming that the packet has already been decrypted.
func (p *PacketPushChallenge) Parse(header *PacketHeader, reader *bytes.Reader) error {
	// Assuming the header has already been read and that the reader is now on the first byte of the data.
	// expectedSize is determined by adding the number of bytes associated with the difficulty (4), challenge, and signature.
	expectedSize := 4 + challenge.ChallengeSize + SignatureSize
	if reader.Len() != expectedSize {
		return fmt.Errorf("packet length not of expected length: expected length: %d, actual length: %d", expectedSize, reader.Len())
	}

	// read difficulty
	binary.Read(reader, binary.BigEndian, &p.Difficulty)

	// read challenge
	chal := make([]byte, challenge.ChallengeSize)
	n, err := reader.Read(chal)
	if err != nil {
		return err
	}
	if n != challenge.ChallengeSize {
		return fmt.Errorf("challenge improperly read: only %d bytes read", n)
	}

	// read signature
	sig, err := parseSignature(reader)
	if err != nil {
		return err
	}

	p.PacketHeader = *header
	p.Challenge = chal
	p.Signature = sig
	return nil
}

// Parse parses the Push packet assuming that the packet has already been decrypted.
func (p *PacketPush) Parse(header *PacketHeader, reader *bytes.Reader) error {
	// Assuming the header has already been read and that the reader is now on the first byte of the data.
	// The 2 comes from \t and \n in <identity>\t<address>\t, each of which requires one byte when assuming UTF-8 encoding.
	minSize := challenge.ChallengeSize + challenge.NonceSize + IdentitySize + 2 + SignatureSize
	if reader.Len() < minSize {
		return fmt.Errorf("packet size too small to contain necessary contents")
	}

	// read challenge
	chal := make([]byte, challenge.ChallengeSize)
	n, err := reader.Read(chal)
	if err != nil {
		return err
	}
	if n != challenge.ChallengeSize {
		return fmt.Errorf("challenge improperly read: only %d bytes read", n)
	}

	// read nonce
	nonce := make([]byte, challenge.NonceSize)
	n, err = reader.Read(nonce)
	if err != nil {
		return err
	}
	if n != challenge.NonceSize {
		return fmt.Errorf("nonce improperly read: only %d bytes read", n)
	}

	// read <identity>\t<address>\n
	nodeTotalSize := reader.Len() - SignatureSize
	// IdentitySize + 2 + 1 gives you the size of the Identity, the length of \n and \t assuming UTF-8 encoding, and the minimum address size.
	if nodeTotalSize <= IdentitySize+2+1 {
		return errors.New("missing <identity>\\t<address>\\n component of PUSH packet")
	}
	nodeBytes := make([]byte, nodeTotalSize)
	_, err = reader.Read(nodeBytes)
	if err != nil {
		return err
	}
	nodes, err := parseNodes(nodeBytes)
	if err != nil {
		return err
	}
	if len(nodes) != 1 {
		return fmt.Errorf("expecting 1 node but received: %d as %+v", len(nodes), nodes)
	}

	// read signature
	sig, err := parseSignature(reader)
	if err != nil {
		return err
	}

	p.PacketHeader = *header
	p.Challenge = chal
	p.Nonce = nonce
	p.Node = nodes[0]
	p.Signature = sig
	return nil
}

// Parse parses the Message packet assuming that the packet has already been decrypted.
func (p *PacketMessage) Parse(header *PacketHeader, reader *bytes.Reader) error {
	// Assuming the header has already been read and that the reader is now on the first byte of the data.
	// mineRequiredSize is derived from adding all of the non-header fields' byte size requirements together with the exclusion of the data field. 1 (TTL, uint8) + 1 (reserved byte) + 2 (DataType, uint16) + SignatureSize.
	minRequiredSize := 1 + 1 + 2 + SignatureSize
	if reader.Len() < minRequiredSize {
		return fmt.Errorf("packet length excluding the header is less than the minimum required size: minimum required size: %d, actual size: %d", minRequiredSize, reader.Len())
	}

	// Read TTL
	binary.Read(reader, binary.BigEndian, &p.TTL)

	// skip over reserved byte
	_, err := reader.ReadByte()
	if err != nil {
		return err
	}

	// Read DataType
	binary.Read(reader, binary.BigEndian, &p.DataType)

	// Read Data
	dataLen := reader.Len() - SignatureSize
	if dataLen < 0 {
		return fmt.Errorf("insufficient space for data and signature in packet")
	}
	var data []byte
	// technically, data could be 0 bytes.
	if dataLen != 0 {
		data = make([]byte, dataLen)
		_, err = reader.Read(data)
		if err != nil {
			return err
		}
	}

	// read signature
	sig, err := parseSignature(reader)
	if err != nil {
		return err
	}

	p.PacketHeader = *header
	p.Data = data
	p.Signature = sig
	return nil
}
