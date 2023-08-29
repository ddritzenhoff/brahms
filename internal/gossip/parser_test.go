package gossip

import (
	"bytes"
	"crypto/sha256"
	"gossiphers/internal/challenge"
	"io"
	"testing"
)

func TestParsePacketHeader(t *testing.T) {
	t.Parallel()
	t.Run("packet header is parsed successfully", func(t *testing.T) {
		var mockSize uint16 = 36
		ph := PacketHeader{
			Size:           mockSize,
			Type:           MessageTypeGossipPing,
			SenderIdentity: make([]byte, IdentitySize),
		}

		phParse, err := ParsePacketHeader(ph.ToBytes())
		if err != nil {
			t.Error(err)
		}
		if phParse.Size != mockSize {
			t.Errorf("phParse.Size incorrect: expected %d, received %d", mockSize, phParse.Size)
		}
		if phParse.Type != MessageTypeGossipPing {
			t.Errorf("phParse.Type incorrect: expected 0x0030, received %x", phParse.Type)
		}
		if !bytes.Equal(phParse.SenderIdentity, ph.SenderIdentity) {
			t.Errorf("phParse.SenderIdentity incorrect: expected %v, received %v", ph.SenderIdentity, phParse.SenderIdentity)
		}
	})
	t.Run("ErrParsePacketHeaderInvalidSize when the header isn't of size PacketHeaderSize", func(t *testing.T) {
		ph := PacketHeader{
			Size:           36,
			Type:           MessageTypeGossipPing,
			SenderIdentity: make([]byte, IdentitySize),
		}

		_, err := ParsePacketHeader(ph.ToBytes()[:35])
		if err != ErrParsePacketHeaderInvalidSize {
			t.Errorf("expecting ErrParsePacketHeaderInvalidSize, got %v", err)
		}
	})
	t.Run("ErrParsePacketHeaderInvalidType if the packet type is not supported", func(t *testing.T) {
		ph := PacketHeader{
			Size:           36,
			Type:           MessageType(0x0000),
			SenderIdentity: make([]byte, IdentitySize),
		}

		_, err := ParsePacketHeader(ph.ToBytes())
		if err != ErrParsePacketHeaderInvalidType {
			t.Errorf("expecting ErrParsePacketHeaderInvalidType, got %v", err)
		}
	})
}

func TestParseSignature(t *testing.T) {
	t.Parallel()
	t.Run("signature is parsed successfully", func(t *testing.T) {
		mockSignature := createMockSignature()
		reader := bytes.NewReader(mockSignature)

		sig, err := parseSignature(reader)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(sig, mockSignature) {
			t.Errorf("sig incorrect: expected %v, received %v", mockSignature, sig)
		}
	})
}

func TestParsePacketPing(t *testing.T) {
	t.Parallel()

	t.Run("packet ping is parsed successfully", func(t *testing.T) {
		// total size of Ping packet must be 2 (Size, uint16) + 2 (Type, uint16) + 32 (SenderIdentity) + 64 (Signature) = 100 bytes
		temp := sha256.Sum256(nil)
		mockSenderIdentity := temp[:]
		mockSignature := createMockSignature()
		ph := PacketHeader{
			Size:           100,
			Type:           MessageTypeGossipPing,
			SenderIdentity: mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		p := PacketPing{
			PacketHeader: ph,
			PacketFooter: pf,
		}

		reader := bytes.NewReader(p.ToBytes())

		if reader.Len() != 100 {
			t.Errorf("expecting 100, got %d", reader.Len())
		}
		_, err := reader.Seek(int64(PacketHeaderSize), io.SeekStart)
		if err != nil {
			t.Error(err)
		}
		if reader.Len() != 64 {
			t.Errorf("expecting 64, got %d", reader.Len())
		}

		var pingPacket PacketPing

		err = pingPacket.Parse(&ph, reader)
		if err != nil {
			t.Error(err)
		}
		if pingPacket.Size != 100 {
			t.Errorf("pingPacket.Size incorrect: expected 100, received %d", pingPacket.Size)
		}
		if pingPacket.Type != MessageTypeGossipPing {
			t.Errorf("pingPacket.Type incorrect: expected 0x0030, received %x", pingPacket.Type)
		}
		if !bytes.Equal(pingPacket.SenderIdentity, mockSenderIdentity) {
			t.Errorf("pingPacket.SenderIdentity incorrect: expected %v, received %v", mockSenderIdentity, pingPacket.SenderIdentity)
		}
		if !bytes.Equal(pingPacket.Signature, mockSignature) {
			t.Errorf("pingPacket.Signature incorrect: expected %v, received %v", mockSignature, pingPacket.Signature)
		}

	})
}

func TestParsePacketPong(t *testing.T) {
	t.Parallel()
	t.Run("packet pong is parsed successfully", func(t *testing.T) {
		mockMessageType := MessageTypeGossipPong
		temp := sha256.Sum256(nil)
		mockSenderIdentity := temp[:]
		mockSignature := createMockSignature()
		ph := PacketHeader{
			Size:           100,
			Type:           mockMessageType,
			SenderIdentity: mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		p := PacketPong{
			PacketHeader: ph,
			PacketFooter: pf,
		}

		reader := bytes.NewReader(p.ToBytes())
		if reader.Len() != 100 {
			t.Errorf("expecting 100, got %d", reader.Len())
		}
		_, err := reader.Seek(int64(PacketHeaderSize), io.SeekStart)
		if err != nil {
			t.Error(err)
		}
		if reader.Len() != 64 {
			t.Errorf("expecting 64, got %d", reader.Len())
		}

		var pongPacket PacketPong

		err = pongPacket.Parse(&ph, reader)
		if err != nil {
			t.Error(err)
		}
		if pongPacket.Size != 100 {
			t.Errorf("Size attribute incorrect: expected 100, received %d", pongPacket.Size)
		}
		if pongPacket.Type != mockMessageType {
			t.Errorf("Type attribute incorrect: expected 0x0030, received %x", pongPacket.Type)
		}
		if !bytes.Equal(pongPacket.SenderIdentity, mockSenderIdentity) {
			t.Errorf("SenderIdentity attribute incorrect: expected %v, received %v", mockSenderIdentity, pongPacket.SenderIdentity)
		}
		if !bytes.Equal(pongPacket.Signature, mockSignature) {
			t.Errorf("Signature attribute incorrect: expected %v, received %v", mockSignature, pongPacket.Signature)
		}
	})
}

func TestParsePacketPullRequest(t *testing.T) {
	t.Parallel()
	t.Run("packet pull request is parsed successfully", func(t *testing.T) {
		mockMessageType := MessageTypeGossipPullRequest
		temp := sha256.Sum256(nil)
		mockSenderIdentity := temp[:]
		mockSignature := createMockSignature()
		ph := PacketHeader{
			Size:           100,
			Type:           mockMessageType,
			SenderIdentity: mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		p := PacketPullRequest{
			PacketHeader: ph,
			PacketFooter: pf,
		}

		reader := bytes.NewReader(p.ToBytes())
		if reader.Len() != 100 {
			t.Errorf("expecting 100, got %d", reader.Len())
		}
		_, err := reader.Seek(int64(PacketHeaderSize), io.SeekStart)
		if err != nil {
			t.Error(err)
		}
		if reader.Len() != 64 {
			t.Errorf("expecting 64, got %d", reader.Len())
		}

		var pullRequest PacketPullRequest

		err = pullRequest.Parse(&ph, reader)
		if err != nil {
			t.Error(err)
		}
		if pullRequest.Size != 100 {
			t.Errorf("Size attribute incorrect: expected 100, received %d", pullRequest.Size)
		}
		if pullRequest.Type != mockMessageType {
			t.Errorf("Type attribute incorrect: expected 0x0030, received %x", pullRequest.Type)
		}
		if !bytes.Equal(pullRequest.SenderIdentity, mockSenderIdentity) {
			t.Errorf("SenderIdentity attribute incorrect: expected %v, received %v", mockSenderIdentity, pullRequest.SenderIdentity)
		}
		if !bytes.Equal(pullRequest.Signature, mockSignature) {
			t.Errorf("Signature attribute incorrect: expected %v, received %v", mockSignature, pullRequest.Signature)
		}
	})
}

func TestParseNodes(t *testing.T) {
	t.Parallel()
	t.Run("greater than one nodes are parsed successfully", func(t *testing.T) {
		mockAddr1 := "1.2.3.4:5678"
		mockIdentity1 := sliceRepeat(IdentitySize, byte(0x01))
		mockNode1, err := NewNode(mockIdentity1, mockAddr1)
		if err != nil {
			t.Error(err)
		}
		mockAddr2 := "5.66.7.8:12"
		mockIdentity2 := sliceRepeat(IdentitySize, byte(0x02))
		mockNode2, err := NewNode(mockIdentity2, mockAddr2)
		if err != nil {
			t.Error(err)
		}

		var mockNodes []byte
		mockNodes = append(mockNodes, mockNode1.ToBytes()...)
		mockNodes = append(mockNodes, mockNode2.ToBytes()...)

		nodes, err := parseNodes(string(mockNodes))
		if err != nil {
			t.Error(err)
		}

		if len(nodes) != 2 {
			t.Errorf("len(nodes) incorrect: expected 2, received %d", len(nodes))
		}

		if !bytes.Equal(nodes[0].Identity, mockIdentity1) {
			t.Errorf("nodes[0].Identity incorrect: expected %v, received %v", mockIdentity1, nodes[0].Identity)
		}
		if nodes[0].Address != mockAddr1 {
			t.Errorf("nodes[0].Address incorrect: expected %s, received %s", mockAddr1, nodes[0].Address)
		}
		if !bytes.Equal(nodes[1].Identity, mockIdentity2) {
			t.Errorf("nodes[1].Identity incorrect: expected %v, received %v", mockIdentity2, nodes[1].Identity)
		}
		if nodes[1].Address != mockAddr2 {
			t.Errorf("nodes[1].Address incorrect: expected %s, received %s", mockAddr2, nodes[1].Address)
		}
	})
	t.Run("one node is parsed successfully", func(t *testing.T) {
		mockAddr1 := "1.2.3.4:5678"
		mockIdentity1 := sliceRepeat(IdentitySize, byte(0x01))
		mockNode1, err := NewNode(mockIdentity1, mockAddr1)
		if err != nil {
			t.Error(err)
		}
		var mockNodes []byte
		mockNodes = append(mockNodes, mockNode1.ToBytes()...)
		nodes, err := parseNodes(string(mockNodes))
		if err != nil {
			t.Error(err)
		}
		if len(nodes) != 1 {
			t.Errorf("len(nodes) incorrect: expected 1, received %d", len(nodes))
		}
		if !bytes.Equal(nodes[0].Identity, mockIdentity1) {
			t.Errorf("nodes[0].Identity incorrect: expected %v, received %v", mockIdentity1, nodes[0].Identity)
		}
		if nodes[0].Address != mockAddr1 {
			t.Errorf("nodes[0].Address incorrect: expected %s, received %s", mockAddr1, nodes[0].Address)
		}
	})
}

func TestParsePacketPullResponse(t *testing.T) {
	t.Parallel()
	t.Run("packet pull response is parsed successfully", func(t *testing.T) {
		mockAddr1 := "1.2.3.4:5678"
		mockIdentity1 := sliceRepeat(IdentitySize, byte(0x01))
		mockNode1, err := NewNode(mockIdentity1, mockAddr1)
		if err != nil {
			t.Error(err)
		}
		mockAddr2 := "5.66.7.8:12"
		mockIdentity2 := sliceRepeat(IdentitySize, byte(0x02))
		mockNode2, err := NewNode(mockIdentity2, mockAddr2)
		if err != nil {
			t.Error(err)
		}
		var mockNodes []byte
		mockNodes = append(mockNodes, mockNode1.ToBytes()...)
		mockNodes = append(mockNodes, mockNode2.ToBytes()...)
		expectedSize := PacketHeaderSize + len(mockNodes) + SignatureSize
		mockMessageType := MessageTypeGossipPullResponse
		temp := sha256.Sum256(nil)
		mockSenderIdentity := temp[:]
		mockSignature := createMockSignature()
		ph := PacketHeader{
			Size:           uint16(expectedSize),
			Type:           mockMessageType,
			SenderIdentity: mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}

		p := PacketPullResponse{
			PacketHeader: ph,
			Nodes:        []Node{*mockNode1, *mockNode2},
			PacketFooter: pf,
		}
		reader := bytes.NewReader(p.ToBytes())
		if reader.Len() != expectedSize {
			t.Errorf("expecting %d, got %d", expectedSize, reader.Len())
		}
		_, err = reader.Seek(int64(PacketHeaderSize), io.SeekStart)
		if err != nil {
			t.Error(err)
		}
		if reader.Len() != expectedSize-PacketHeaderSize {
			t.Errorf("expecting %d, got %d", expectedSize-PacketHeaderSize, reader.Len())
		}

		var pullResponse PacketPullResponse
		err = pullResponse.Parse(&ph, reader)
		if err != nil {
			t.Error(err)
		}
		if pullResponse.Size != uint16(expectedSize) {
			t.Errorf("Size attribute incorrect: expected %d, received %d", expectedSize, pullResponse.Size)
		}
		if pullResponse.Type != mockMessageType {
			t.Errorf("Type attribute incorrect: expected 0x0030, received %x", pullResponse.Type)
		}
		if !bytes.Equal(pullResponse.SenderIdentity, mockSenderIdentity) {
			t.Errorf("SenderIdentity attribute incorrect: expected %v, received %v", mockSenderIdentity, pullResponse.SenderIdentity)
		}
		if !bytes.Equal(pullResponse.Signature, mockSignature) {
			t.Errorf("Signature attribute incorrect: expected %v, received %v", mockSignature, pullResponse.Signature)
		}
		if len(pullResponse.Nodes) != 2 {
			t.Errorf("len(nodes) incorrect: expected 2, received %d", len(pullResponse.Nodes))
		}
		if !bytes.Equal(pullResponse.Nodes[0].Identity, mockIdentity1) {
			t.Errorf("nodes[0].Identity incorrect: expected %v, received %v", mockIdentity1, pullResponse.Nodes[0].Identity)
		}
		if pullResponse.Nodes[0].Address != mockAddr1 {
			t.Errorf("nodes[0].Address incorrect: expected %s, received %s", mockAddr1, pullResponse.Nodes[0].Address)
		}
		if !bytes.Equal(pullResponse.Nodes[1].Identity, mockIdentity2) {
			t.Errorf("nodes[1].Identity incorrect: expected %v, received %v", mockIdentity2, pullResponse.Nodes[1].Identity)
		}
		if pullResponse.Nodes[1].Address != mockAddr2 {
			t.Errorf("nodes[1].Address incorrect: expected %s, received %s", mockAddr2, pullResponse.Nodes[1].Address)
		}
	})
}

func TestParsePacketPushRequest(t *testing.T) {
	t.Parallel()
	t.Run("packet push request is parsed successfully", func(t *testing.T) {
		mockMessageType := MessageTypeGossipPushRequest
		temp := sha256.Sum256(nil)
		mockSenderIdentity := temp[:]
		mockSignature := createMockSignature()
		ph := PacketHeader{
			Size:           100,
			Type:           mockMessageType,
			SenderIdentity: mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		p := PacketPushRequest{
			PacketHeader: ph,
			PacketFooter: pf,
		}

		reader := bytes.NewReader(p.ToBytes())
		if reader.Len() != 100 {
			t.Errorf("expecting 100, got %d", reader.Len())
		}
		_, err := reader.Seek(int64(PacketHeaderSize), io.SeekStart)
		if err != nil {
			t.Error(err)
		}
		if reader.Len() != 64 {
			t.Errorf("expecting 64, got %d", reader.Len())
		}

		var pushRequest PacketPushRequest

		err = pushRequest.Parse(&ph, reader)
		if err != nil {
			t.Error(err)
		}
		if pushRequest.Size != 100 {
			t.Errorf("Size attribute incorrect: expected 100, received %d", pushRequest.Size)
		}
		if pushRequest.Type != mockMessageType {
			t.Errorf("Type attribute incorrect: expected 0x0030, received %x", pushRequest.Type)
		}
		if !bytes.Equal(pushRequest.SenderIdentity, mockSenderIdentity) {
			t.Errorf("SenderIdentity attribute incorrect: expected %v, received %v", mockSenderIdentity, pushRequest.SenderIdentity)
		}
		if !bytes.Equal(pushRequest.Signature, mockSignature) {
			t.Errorf("Signature attribute incorrect: expected %v, received %v", mockSignature, pushRequest.Signature)
		}
	})
}

func TestParsePacketPushChallenge(t *testing.T) {
	t.Parallel()
	t.Run("packet push challenge is parsed successfully", func(t *testing.T) {
		mockMessageType := MessageTypeGossipPushChallenge
		temp := sha256.Sum256(nil)
		mockSenderIdentity := temp[:]
		mockSignature := createMockSignature()
		expectedSize := PacketHeaderSize + 4 + challenge.ChallengeSize + SignatureSize
		ph := PacketHeader{
			Size:           uint16(expectedSize),
			Type:           mockMessageType,
			SenderIdentity: mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		mockDifficulty := uint32(43)
		mockChallenge := sliceRepeat(challenge.ChallengeSize, byte(0x01))
		p := PacketPushChallenge{
			PacketHeader: ph,
			Difficulty:   mockDifficulty,
			Challenge:    mockChallenge,
			PacketFooter: pf,
		}

		reader := bytes.NewReader(p.ToBytes())
		if reader.Len() != expectedSize {
			t.Errorf("expecting %d, got %d", expectedSize, reader.Len())
		}
		_, err := reader.Seek(int64(PacketHeaderSize), io.SeekStart)
		if err != nil {
			t.Error(err)
		}
		if reader.Len() != expectedSize-PacketHeaderSize {
			t.Errorf("expecting %d, got %d", expectedSize-PacketHeaderSize, reader.Len())
		}

		var pushChallenge PacketPushChallenge
		pushChallenge.Parse(&ph, reader)
		if pushChallenge.Size != uint16(expectedSize) {
			t.Errorf("Size attribute incorrect: expected %d, received %d", expectedSize, pushChallenge.Size)
		}
		if pushChallenge.Type != mockMessageType {
			t.Errorf("Type attribute incorrect: expected 0x0051, received %x", pushChallenge.Type)
		}
		if !bytes.Equal(pushChallenge.SenderIdentity, mockSenderIdentity) {
			t.Errorf("SenderIdentity attribute incorrect: expected %v, received %v", mockSenderIdentity, pushChallenge.SenderIdentity)
		}
		if !bytes.Equal(pushChallenge.Signature, mockSignature) {
			t.Errorf("Signature attribute incorrect: expected %v, received %v", mockSignature, pushChallenge.Signature)
		}
		if pushChallenge.Difficulty != mockDifficulty {
			t.Errorf("Difficulty attribute incorrect: expected %d, received %d", mockDifficulty, pushChallenge.Difficulty)
		}
		if !bytes.Equal(pushChallenge.Challenge, mockChallenge) {
			t.Errorf("Challenge attribute incorrect: expected %v, received %v", mockChallenge, pushChallenge.Challenge)
		}
	})
}

func TestParsePacketPush(t *testing.T) {
	t.Parallel()
	t.Run("packet push is parsed successfully", func(t *testing.T) {
		mockAddr1 := "1.2.3.4:5678"
		mockIdentity1 := sliceRepeat(IdentitySize, byte(0x01))
		mockNode1, err := NewNode(mockIdentity1, mockAddr1)
		if err != nil {
			t.Error(err)
		}
		mockNodes := mockNode1.ToBytes()

		mockMessageType := MessageTypeGossipPush
		temp := sha256.Sum256(nil)
		mockSenderIdentity := temp[:]
		mockSignature := createMockSignature()
		expectedSize := PacketHeaderSize + challenge.ChallengeSize + challenge.NonceSize + len(mockNodes) + SignatureSize
		ph := PacketHeader{
			Size:           uint16(expectedSize),
			Type:           mockMessageType,
			SenderIdentity: mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		p := PacketPush{
			PacketHeader: ph,
			Challenge:    sliceRepeat(challenge.ChallengeSize, byte(0x24)),
			Nonce:        sliceRepeat(challenge.NonceSize, byte(0x42)),
			Node:         *mockNode1,
			PacketFooter: pf,
		}

		reader := bytes.NewReader(p.ToBytes())
		if reader.Len() != expectedSize {
			t.Errorf("expecting %d, got %d", expectedSize, reader.Len())
		}
		_, err = reader.Seek(int64(PacketHeaderSize), io.SeekStart)
		if err != nil {
			t.Error(err)
		}
		if reader.Len() != expectedSize-PacketHeaderSize {
			t.Errorf("expecting %d, got %d", expectedSize-PacketHeaderSize, reader.Len())
		}

		var push PacketPush
		err = push.Parse(&ph, reader)
		if err != nil {
			t.Error(err)
		}
		if push.Size != uint16(expectedSize) {
			t.Errorf("Size attribute incorrect: expected %d, received %d", expectedSize, push.Size)
		}
		if push.Type != mockMessageType {
			t.Errorf("Type attribute incorrect: expected 0x0052, received %x", push.Type)
		}
		if !bytes.Equal(push.SenderIdentity, mockSenderIdentity) {
			t.Errorf("SenderIdentity attribute incorrect: expected %v, received %v", mockSenderIdentity, push.SenderIdentity)
		}
		if !bytes.Equal(push.Signature, mockSignature) {
			t.Errorf("Signature attribute incorrect: expected %v, received %v", mockSignature, push.Signature)
		}
		if !bytes.Equal(push.Challenge, sliceRepeat(challenge.ChallengeSize, byte(0x24))) {
			t.Errorf("Challenge attribute incorrect: expected %v, received %v", sliceRepeat(challenge.ChallengeSize, byte(0x24)), push.Challenge)
		}
		if !bytes.Equal(push.Nonce, sliceRepeat(challenge.NonceSize, byte(0x42))) {
			t.Errorf("Nonce attribute incorrect: expected %v, received %v", sliceRepeat(challenge.NonceSize, byte(0x42)), push.Nonce)
		}
		if !bytes.Equal(push.Node.Identity, mockIdentity1) {
			t.Errorf("Node.Identity attribute incorrect: expected %v, received %v", mockIdentity1, push.Node.Identity)
		}
		if push.Node.Address != mockAddr1 {
			t.Errorf("Node.Address attribute incorrect: expected %s, received %s", mockAddr1, push.Node.Address)
		}
	})
}

func TestParsePacketMessage(t *testing.T) {
	t.Parallel()
	t.Run("packet message is parsed successfully", func(t *testing.T) {
		mockData := []byte("hello world!!")
		mockTTL := 5
		mockMessageType := MessageTypeGossipMessage
		temp := sha256.Sum256(nil)
		mockSenderIdentity := temp[:]
		mockSignature := createMockSignature()
		// 1 --> TTL, 1 --> reserved, 2 --> DataType
		expectedSize := PacketHeaderSize + 1 + 1 + 2 + len(mockData) + SignatureSize
		ph := PacketHeader{
			Size:           uint16(expectedSize),
			Type:           mockMessageType,
			SenderIdentity: mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		p := PacketMessage{
			PacketHeader: ph,
			TTL:          uint8(mockTTL),
			DataType:     uint16(0x1234),
			Data:         mockData,
			PacketFooter: pf,
		}

		reader := bytes.NewReader(p.ToBytes())
		if reader.Len() != expectedSize {
			t.Errorf("expecting %d, got %d", expectedSize, reader.Len())
		}
		_, err := reader.Seek(int64(PacketHeaderSize), io.SeekStart)
		if err != nil {
			t.Error(err)
		}
		if reader.Len() != expectedSize-PacketHeaderSize {
			t.Errorf("expecting %d, got %d", expectedSize-PacketHeaderSize, reader.Len())
		}

		var message PacketMessage
		err = message.Parse(&ph, reader)
		if err != nil {
			t.Error(err)
		}
		if message.Size != uint16(expectedSize) {
			t.Errorf("Size attribute incorrect: expected %d, received %d", expectedSize, message.Size)
		}
		if message.Type != mockMessageType {
			t.Errorf("Type attribute incorrect: expected 0x0052, received %x", message.Type)
		}
		if !bytes.Equal(message.SenderIdentity, mockSenderIdentity) {
			t.Errorf("SenderIdentity attribute incorrect: expected %v, received %v", mockSenderIdentity, message.SenderIdentity)
		}
		if !bytes.Equal(message.Signature, mockSignature) {
			t.Errorf("Signature attribute incorrect: expected %v, received %v", mockSignature, message.Signature)
		}
		if message.TTL != uint8(mockTTL) {
			t.Errorf("TTL attribute incorrect: expected %d, received %d", mockTTL, message.TTL)
		}
		if message.DataType != uint16(0x1234) {
			t.Errorf("DataType attribute incorrect: expected %d, received %d", uint16(0x1234), message.DataType)
		}
		if !bytes.Equal(message.Data, mockData) {
			t.Errorf("Data attribute incorrect: expected %v, received %v", mockData, message.Data)
		}
	})
}
