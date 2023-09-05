package gossip

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"gossiphers/internal/challenge"
	"testing"
	"time"
)

func TestIdentity_ToBytes(t *testing.T) {
	t.Parallel()
	t.Run("identity is serialized successfully to a byte slice", func(t *testing.T) {
		// Create an Identity value for testing
		id := Identity("test_identity")

		// Call the ToBytes method to get the byte slice
		b := id.ToBytes()

		// Define the expected byte slice based on the string representation
		expectedBytes := []byte(id)

		// Compare the actual bytes with the expected bytes
		if !bytes.Equal(b, expectedBytes) {
			t.Errorf("ToBytes() = %v, want %v", b, expectedBytes)
		}
	})
}

func TestNode_ToBytes(t *testing.T) {
	t.Parallel()
	t.Run("node is serialized successfully to byte slice", func(t *testing.T) {
		mockIdentity := sliceRepeat(IdentitySize, byte(0x12))
		mockAddr := "1.2.3.4:5678"
		node, err := NewNode(mockIdentity, mockAddr)
		if err != nil {
			t.Error(err)
		}
		byteNode := node.ToBytes()
		if !bytes.Equal(byteNode[0:IdentitySize], mockIdentity) {
			t.Errorf("Identity incorrect: expected %v, received %v", mockIdentity, byteNode[0:IdentitySize])
		}
		delim1 := string(byteNode[IdentitySize : IdentitySize+1])
		if delim1 != "\t" {
			t.Errorf("First delimiter incorrect: expected %s, received %s", "\t", delim1)
		}
		addr := byteNode[IdentitySize+1 : len(byteNode)-1]
		if !bytes.Equal(addr, []byte(mockAddr)) {
			t.Errorf("Address incorrect: expected %s, received %s", mockAddr, string(addr))
		}
		delim2 := string(byteNode[len(byteNode)-1:])
		if delim2 != "\n" {
			t.Errorf("Second delimiter incorrect: expected %s, received %s", "\n", delim2)
		}
	})
}

func TestPacketHeader_ToBytes(t *testing.T) {
	t.Parallel()
	t.Run("header packet is serialized successfully to byte slice", func(t *testing.T) {
		var mockSize uint16 = 44
		mockMessageType := MessageTypeGossipPong
		temp := sha256.Sum256(nil)
		mockSenderIdentity, err := NewIdentity(temp[:])
		if err != nil {
			t.Error(err)
		}
		mockTimestamp := uint64(time.Now().UnixMilli())
		packetHeader := PacketHeader{
			Size:           mockSize,
			Type:           mockMessageType,
			Timestamp:      mockTimestamp,
			SenderIdentity: *mockSenderIdentity,
		}
		bytesPacketHeader := packetHeader.ToBytes()
		reader := bytes.NewReader(bytesPacketHeader)

		// size
		var size uint16
		binary.Read(reader, binary.BigEndian, &size)
		if size != mockSize {
			t.Errorf("header size attribute incorrect: expected %d, received %d", mockSize, size)
		}

		// type
		var mt MessageType
		binary.Read(reader, binary.BigEndian, &mt)
		if mt != mockMessageType {
			t.Errorf("header message type attribute incorrect: expected %x, received %x", mockMessageType, mt)
		}

		// timestamp
		var timestamp uint64
		binary.Read(reader, binary.BigEndian, &timestamp)
		if timestamp != mockTimestamp {
			t.Errorf("header timestamo attribute incorrect: expected %x, received %x", mockMessageType, mt)
		}

		// sender identity
		si := make([]byte, IdentitySize)
		n, err := reader.Read(si)
		if err != nil {
			t.Error(err)
		}
		if n != IdentitySize {
			t.Errorf("could not read expected number of bytes: expected %d, received %d", IdentitySize, n)
		}
		if !bytes.Equal(si, mockSenderIdentity.ToBytes()) {
			t.Errorf("header sender identity attribute incorrect: expected %v, received %v", mockSenderIdentity, si)
		}
	})
}

func TestPacketFooter_ToBytes(t *testing.T) {
	t.Parallel()
	t.Run("footer packet is serialized successfully to byte slice", func(t *testing.T) {
		mockSignature := createMockSignature()
		pf := PacketFooter{
			Signature: mockSignature,
		}
		pfBytes := pf.ToBytes()
		reader := bytes.NewReader(pfBytes)

		// signature
		sig := make([]byte, SignatureSize)
		n, err := reader.Read(sig)
		if err != nil {
			t.Error(err)
		}
		if n != SignatureSize {
			t.Errorf("could not read expected number of bytes: expected %d, received %d", SignatureSize, n)
		}
		if !bytes.Equal(sig, mockSignature) {
			t.Errorf("footer signature incorrect: expected %v, received %v", mockSignature, sig)
		}
	})
}

func TestPacketPing_ToBytes(t *testing.T) {
	t.Parallel()
	t.Run("packet ping is serialized successfully to byte slice", func(t *testing.T) {
		mockType := MessageTypeGossipPing
		temp := sha256.Sum256(nil)
		mockSenderIdentity, err := NewIdentity(temp[:])
		mockTimestamp := uint64(time.Now().UnixMilli())
		if err != nil {
			t.Error(err)
		}
		mockSignature := createMockSignature()
		ph := PacketHeader{
			Size:           100,
			Type:           mockType,
			Timestamp:      mockTimestamp,
			SenderIdentity: *mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		p := PacketPing{
			PacketHeader: ph,
			PacketFooter: pf,
		}

		b := p.ToBytes()
		if len(b) != 556 {
			t.Errorf("wrong binary blob size: expected 556, received %d", len(b))
		}
		size := binary.BigEndian.Uint16(b[0:2])
		if size != 100 {
			t.Errorf("pingPacket.Size incorrect: expected 100, received %d", size)
			return
		}
		ty := binary.BigEndian.Uint16(b[2:4])
		if MessageType(ty) != mockType {
			t.Errorf("pingPacket.Type incorrect: expected 0x0030, received %x", ty)
		}
		ts := binary.BigEndian.Uint64(b[4:12])
		if ts != mockTimestamp {
			t.Errorf("pingPacket.Timestamp incorrect")
		}
		si := b[12:44]
		if !bytes.Equal(si, mockSenderIdentity.ToBytes()) {
			t.Errorf("pingPacket.SenderIdentity incorrect: expected %v, received %v", mockSenderIdentity, si)
		}
		sig := b[44:]
		if !bytes.Equal(sig, mockSignature) {
			t.Errorf("pingPacket.Signature incorrect: expected %v, received %v", mockSignature, sig)
		}
	})
}

func TestPacketPong_ToBytes(t *testing.T) {
	t.Parallel()
	t.Run("packet pong is serialized successfully to byte slice", func(t *testing.T) {
		mockType := MessageTypeGossipPong
		temp := sha256.Sum256(nil)
		mockSenderIdentity, err := NewIdentity(temp[:])
		mockTimestamp := uint64(time.Now().UnixMilli())
		if err != nil {
			t.Error(err)
		}
		mockSignature := createMockSignature()
		ph := PacketHeader{
			Size:           100,
			Type:           mockType,
			Timestamp:      mockTimestamp,
			SenderIdentity: *mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		p := PacketPong{
			PacketHeader: ph,
			PacketFooter: pf,
		}

		b := p.ToBytes()
		if len(b) != 556 {
			t.Errorf("wrong binary blob size: expected 556, received %d", len(b))
		}
		size := binary.BigEndian.Uint16(b[0:2])
		if size != 100 {
			t.Errorf("pingPacket.Size incorrect: expected 100, received %d", size)
			return
		}
		ty := binary.BigEndian.Uint16(b[2:4])
		if MessageType(ty) != mockType {
			t.Errorf("pingPacket.Type incorrect: expected 0x0030, received %x", ty)
		}
		si := b[12:44]
		if !bytes.Equal(si, mockSenderIdentity.ToBytes()) {
			t.Errorf("pingPacket.SenderIdentity incorrect: expected %v, received %v", mockSenderIdentity, si)
		}
		sig := b[44:]
		if !bytes.Equal(sig, mockSignature) {
			t.Errorf("pingPacket.Signature incorrect: expected %v, received %v", mockSignature, sig)
		}
	})
}

func TestPacketPullRequest_ToBytes(t *testing.T) {
	t.Parallel()
	t.Run("packet pull request is serialized successfully to byte slice", func(t *testing.T) {
		mockType := MessageTypeGossipPullRequest
		temp := sha256.Sum256(nil)
		mockSenderIdentity, err := NewIdentity(temp[:])
		mockTimestamp := uint64(time.Now().UnixMilli())
		if err != nil {
			t.Error(err)
		}
		mockSignature := createMockSignature()
		ph := PacketHeader{
			Size:           100,
			Type:           mockType,
			Timestamp:      mockTimestamp,
			SenderIdentity: *mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		p := PacketPullRequest{
			PacketHeader: ph,
			PacketFooter: pf,
		}

		b := p.ToBytes()
		if len(b) != 556 {
			t.Errorf("wrong binary blob size: expected 556, received %d", len(b))
		}
		size := binary.BigEndian.Uint16(b[0:2])
		if size != 100 {
			t.Errorf("pingPacket.Size incorrect: expected 100, received %d", size)
			return
		}
		ty := binary.BigEndian.Uint16(b[2:4])
		if MessageType(ty) != mockType {
			t.Errorf("pingPacket.Type incorrect: expected 0x0030, received %x", ty)
		}
		si := b[12:44]
		if !bytes.Equal(si, mockSenderIdentity.ToBytes()) {
			t.Errorf("pingPacket.SenderIdentity incorrect: expected %v, received %v", mockSenderIdentity, si)
		}
		sig := b[44:]
		if !bytes.Equal(sig, mockSignature) {
			t.Errorf("pingPacket.Signature incorrect: expected %v, received %v", mockSignature, sig)
		}
	})
}

func TestPacketPullResponse_ToBytes(t *testing.T) {
	t.Parallel()
	t.Run("packet pull response is serialized successfully to byte slice", func(t *testing.T) {
		var mockSize uint16 = 128
		temp := sha256.Sum256(nil)
		mockSenderIdentity, err := NewIdentity(temp[:])
		mockTimestamp := uint64(time.Now().UnixMilli())
		if err != nil {
			t.Error(err)
		}
		mockSignature := createMockSignature()
		ph := PacketHeader{
			Size:           mockSize,
			Type:           MessageTypeGossipPullResponse,
			Timestamp:      mockTimestamp,
			SenderIdentity: *mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}

		mockAddr1 := "1.2.3.4:5678"
		mockIdentity1 := sliceRepeat(IdentitySize, byte(0x01))
		node1, err := NewNode(mockIdentity1, mockAddr1)
		if err != nil {
			t.Error(err)
		}

		mockAddr2 := "3.4.5.6:7"
		mockIdentity2 := sliceRepeat(IdentitySize, byte(0x11))
		node2, err := NewNode(mockIdentity2, mockAddr2)
		if err != nil {
			t.Error(err)
		}

		mockAddr3 := "5.63.7.8:12"
		mockIdentity3 := sliceRepeat(IdentitySize, byte(0x11))
		node3, err := NewNode(mockIdentity3, mockAddr3)
		if err != nil {
			t.Error(err)
		}

		p := PacketPullResponse{
			PacketHeader: ph,
			Nodes:        []Node{*node1, *node2, *node3},
			PacketFooter: pf,
		}

		b := p.ToBytes()

		size := binary.BigEndian.Uint16(b[0:2])
		if size != mockSize {
			t.Errorf("packet size attribute incorrect: expected %d, received %d", mockSize, size)
			return
		}
		ty := binary.BigEndian.Uint16(b[2:4])
		if MessageType(ty) != MessageTypeGossipPullResponse {
			t.Errorf("packet message type incorrect: expected 0x0030, received %x", ty)
		}
		si := b[12:44]
		if !bytes.Equal(si, mockSenderIdentity.ToBytes()) {
			t.Errorf("packet sender identity incorrect: expected %v, received %v", mockSenderIdentity, si)
		}

		// nodes --> <Identity1>\t<Address1>\n<Identity2>\t<Address2>\n<Identity3>\t<Address3>\n

		// node1
		id1 := b[44 : 44+IdentitySize]
		if !bytes.Equal(id1, mockIdentity1) {
			t.Errorf("packet identity1 incorrect: expected %v, received %v", mockIdentity1, id1)
		}
		t1 := string(b[44+IdentitySize : 44+IdentitySize+1])
		if t1 != "\t" {
			t.Errorf("packet \\t incorrect: expected %s, received %s", "\t", t1)
		}
		addr1 := string(b[44+IdentitySize+1 : 44+IdentitySize+1+len(mockAddr1)])
		if addr1 != mockAddr1 {
			t.Errorf("packet address1 incorrect: expected: %s, received %s", mockAddr1, addr1)
		}
		n1 := string(b[44+IdentitySize+1+len(mockAddr1) : 44+IdentitySize+1+len(mockAddr1)+1])
		if n1 != "\n" {
			t.Errorf("packet \\n incorrect: expected %s, received %s", "\n", n1)
		}

		// node2
		node2Start := 44 + IdentitySize + 1 + len(mockAddr1) + 1
		id2 := b[node2Start : node2Start+IdentitySize]
		if !bytes.Equal(id2, mockIdentity2) {
			t.Errorf("packet identity2 incorrect: expected %v, received %v", mockIdentity2, id2)
		}
		t2 := string(b[node2Start+IdentitySize : node2Start+IdentitySize+1])
		if t2 != "\t" {
			t.Errorf("packet \\t incorrect: expected %s, received %s", "\t", t2)
		}
		addr2 := string(b[node2Start+IdentitySize+1 : node2Start+IdentitySize+1+len(mockAddr2)])
		if addr2 != mockAddr2 {
			t.Errorf("packet address2 incorrect: expected: %s, received %s", mockAddr2, addr2)
		}
		n2 := string(b[node2Start+IdentitySize+1+len(mockAddr2) : node2Start+IdentitySize+1+len(mockAddr2)+1])
		if n2 != "\n" {
			t.Errorf("packet \\n incorrect: expected %s, received %s", "\n", n2)
		}

		// node3
		node3Start := node2Start + IdentitySize + 1 + len(mockAddr2) + 1
		id3 := b[node3Start : node3Start+IdentitySize]
		if !bytes.Equal(id3, mockIdentity3) {
			t.Errorf("packet identity3 incorrect: expected %v, received %v", mockIdentity3, id3)
		}
		t3 := string(b[node3Start+IdentitySize : node3Start+IdentitySize+1])
		if t3 != "\t" {
			t.Errorf("packet \\t incorrect: expected %s, received %s", "\t", t3)
		}
		addr3 := string(b[node3Start+IdentitySize+1 : node3Start+IdentitySize+1+len(mockAddr3)])
		if addr3 != mockAddr3 {
			t.Errorf("packet address3 incorrect: expected: %s, received %s", mockAddr3, addr3)
		}
		n3 := string(b[node3Start+IdentitySize+1+len(mockAddr3) : node3Start+IdentitySize+1+len(mockAddr3)+1])
		if n3 != "\n" {
			t.Errorf("packet \\n incorrect: expected %s, received %s", "\n", n3)
		}

		// packet footer
		packetFooterStart := node3Start + IdentitySize + 1 + len(mockAddr3) + 1
		sig := b[packetFooterStart : packetFooterStart+SignatureSize]
		if !bytes.Equal(sig, mockSignature) {
			t.Errorf("packet signature incorrect: expected %v, received %v", mockSignature, sig)
		}
	})
}

func TestPacketPushRequest_ToBytes(t *testing.T) {
	t.Parallel()
	t.Run("packet push request is serialized successfully to byte slice", func(t *testing.T) {
		mockType := MessageTypeGossipPushRequest
		temp := sha256.Sum256(nil)
		mockSenderIdentity, err := NewIdentity(temp[:])
		mockTimestamp := uint64(time.Now().UnixMilli())
		if err != nil {
			t.Error(err)
		}
		mockSignature := createMockSignature()
		ph := PacketHeader{
			Size:           100,
			Type:           mockType,
			Timestamp:      mockTimestamp,
			SenderIdentity: *mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		p := PacketPushRequest{
			PacketHeader: ph,
			PacketFooter: pf,
		}

		b := p.ToBytes()
		if len(b) != 556 {
			t.Errorf("wrong binary blob size: expected 556, received %d", len(b))
		}
		size := binary.BigEndian.Uint16(b[0:2])
		if size != 100 {
			t.Errorf("pingPacket.Size incorrect: expected 100, received %d", size)
			return
		}
		ty := binary.BigEndian.Uint16(b[2:4])
		if MessageType(ty) != mockType {
			t.Errorf("pingPacket.Type incorrect: expected 0x0030, received %x", ty)
		}
		si := b[12:44]
		if !bytes.Equal(si, mockSenderIdentity.ToBytes()) {
			t.Errorf("pingPacket.SenderIdentity incorrect: expected %v, received %v", mockSenderIdentity, si)
		}
		sig := b[44:]
		if !bytes.Equal(sig, mockSignature) {
			t.Errorf("pingPacket.Signature incorrect: expected %v, received %v", mockSignature, sig)
		}
	})
}

func TestPacketPushChallenge_ToBytes(t *testing.T) {
	t.Parallel()
	t.Run("packet push challenge is serialized successfully to byte slice", func(t *testing.T) {
		var mockSize uint16 = 104
		temp := sha256.Sum256(nil)
		mockSenderIdentity, err := NewIdentity(temp[:])
		mockTimestamp := uint64(time.Now().UnixMilli())
		if err != nil {
			t.Error(err)
		}
		mockSignature := createMockSignature()
		ph := PacketHeader{
			Size:           mockSize,
			Type:           MessageTypeGossipPushChallenge,
			Timestamp:      mockTimestamp,
			SenderIdentity: *mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		mockDifficulty := uint32(1234567890)
		mockChallenge := sliceRepeat(32, byte(0x12))
		p := PacketPushChallenge{
			PacketHeader: ph,
			Difficulty:   mockDifficulty,
			Challenge:    mockChallenge,
			PacketFooter: pf,
		}

		b := p.ToBytes()

		size := binary.BigEndian.Uint16(b[0:2])
		if size != mockSize {
			t.Errorf("packet size attribute incorrect: expected %d, received %d", mockSize, size)
			return
		}
		ty := binary.BigEndian.Uint16(b[2:4])
		if MessageType(ty) != MessageTypeGossipPushChallenge {
			t.Errorf("packet message type incorrect: expected 0x0030, received %x", ty)
		}
		si := b[12:44]
		if !bytes.Equal(si, mockSenderIdentity.ToBytes()) {
			t.Errorf("packet sender identity incorrect: expected %v, received %v", mockSenderIdentity, si)
		}
		difficulty := binary.BigEndian.Uint32(b[44:48])
		if difficulty != mockDifficulty {
			t.Errorf("packet difficulty incorrect: expected %d, received %d", mockDifficulty, difficulty)
		}
		challenge := b[48 : 48+32]
		if !bytes.Equal(challenge, mockChallenge) {
			t.Errorf("packet challenge incorrect: expected %v, received %v", mockChallenge, challenge)
		}
		sig := b[80:]
		if !bytes.Equal(sig, mockSignature) {
			t.Errorf("packet signature incorrect: expected %v, received %v", mockSignature, sig)
		}
	})
}

func TestPacketPush_ToBytes(t *testing.T) {
	t.Parallel()
	t.Run("packet push is serialized successfully to byte slice", func(t *testing.T) {
		var mockSize uint16 = 136
		temp := sha256.Sum256(nil)
		mockSenderIdentity, err := NewIdentity(temp[:])
		mockTimestamp := uint64(time.Now().UnixMilli())
		if err != nil {
			t.Error(err)
		}
		mockSignature := createMockSignature()
		ph := PacketHeader{
			Size:           mockSize,
			Type:           MessageTypeGossipPush,
			Timestamp:      mockTimestamp,
			SenderIdentity: *mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		mockChallenge := sliceRepeat(challenge.ChallengeSize, byte(0x12))
		mockNonce := sliceRepeat(challenge.NonceSize, byte(0x34))
		mockAddr := "1.2.32.4:329"
		mockIdentity := sliceRepeat(IdentitySize, byte(0x56))
		node, err := NewNode(mockIdentity, mockAddr)
		if err != nil {
			t.Error(err)
		}
		p := PacketPush{
			PacketHeader: ph,
			Challenge:    mockChallenge,
			Nonce:        mockNonce,
			Node:         *node,
			PacketFooter: pf,
		}
		b := p.ToBytes()

		size := binary.BigEndian.Uint16(b[0:2])
		if size != mockSize {
			t.Errorf("packet size attribute incorrect: expected %d, received %d", mockSize, size)
			return
		}
		ty := binary.BigEndian.Uint16(b[2:4])
		if MessageType(ty) != MessageTypeGossipPush {
			t.Errorf("packet message type incorrect: expected 0x0030, received %x", ty)
		}
		si := b[12:44]
		if !bytes.Equal(si, mockSenderIdentity.ToBytes()) {
			t.Errorf("packet sender identity incorrect: expected %v, received %v", mockSenderIdentity, si)
		}
		ch := b[44 : 44+challenge.ChallengeSize]
		if !bytes.Equal(ch, mockChallenge) {
			t.Errorf("packet challenge incorrect: expected %v, received %v", mockChallenge, ch)
		}
		nonce := b[44+challenge.ChallengeSize : 44+challenge.ChallengeSize+challenge.NonceSize]
		if !bytes.Equal(nonce, mockNonce) {
			t.Errorf("packet nonce incorrect: expected %v, received %v", mockNonce, nonce)
		}
		// node --> <Identity>\t<Address>\n
		id := b[44+challenge.ChallengeSize+challenge.NonceSize : 44+challenge.ChallengeSize+challenge.NonceSize+IdentitySize]
		if !bytes.Equal(id, mockIdentity) {
			t.Errorf("packet identity incorrect: expected %v, received %v", mockIdentity, id)
		}
		t1 := string(b[44+challenge.ChallengeSize+challenge.NonceSize+IdentitySize : 44+challenge.ChallengeSize+challenge.NonceSize+IdentitySize+1])
		if t1 != "\t" {
			t.Errorf("packet \\t incorrect: expected %s, received %s", "\t", t1)
		}
		addr := string(b[44+challenge.ChallengeSize+challenge.NonceSize+IdentitySize+1 : 44+challenge.ChallengeSize+challenge.NonceSize+IdentitySize+1+len(mockAddr)])
		if addr != mockAddr {
			t.Errorf("packet address incorrect: expected: %s, received %s", mockAddr, addr)
		}
		n1 := string(b[44+challenge.ChallengeSize+challenge.NonceSize+IdentitySize+1+len(mockAddr) : 44+challenge.ChallengeSize+challenge.NonceSize+IdentitySize+1+len(mockAddr)+1])
		if n1 != "\n" {
			t.Errorf("packet \\n incorrect: expected %s, received %s", "\n", n1)
		}
		sig := b[44+challenge.ChallengeSize+challenge.NonceSize+IdentitySize+1+len(mockAddr)+1 : 44+challenge.ChallengeSize+challenge.NonceSize+IdentitySize+1+len(mockAddr)+1+SignatureSize]
		if !bytes.Equal(sig, mockSignature) {
			t.Errorf("packet signature incorrect: expected %v, received %v", mockSignature, sig)
		}
	})
}

func TestPacketMessage_ToBytes(t *testing.T) {
	t.Parallel()
	t.Run("packet message is serialized successfully to byte slice", func(t *testing.T) {
		var mockSize uint16 = 136
		temp := sha256.Sum256(nil)
		mockSenderIdentity, err := NewIdentity(temp[:])
		mockTimestamp := uint64(time.Now().UnixMilli())
		if err != nil {
			t.Error(err)
		}
		mockSignature := createMockSignature()
		ph := PacketHeader{
			Size:           mockSize,
			Type:           MessageTypeGossipPush,
			Timestamp:      mockTimestamp,
			SenderIdentity: *mockSenderIdentity,
		}
		pf := PacketFooter{
			Signature: mockSignature,
		}
		mockTTL := uint8(123)
		mockDataType := uint16(456)
		mockData := sliceRepeat(91, byte(0x12))
		p := PacketMessage{
			PacketHeader: ph,
			TTL:          mockTTL,
			DataType:     mockDataType,
			Data:         mockData,
			PacketFooter: pf,
		}
		b := p.ToBytes()
		size := binary.BigEndian.Uint16(b[0:2])
		if size != mockSize {
			t.Errorf("packet size attribute incorrect: expected %d, received %d", mockSize, size)
			return
		}
		ty := binary.BigEndian.Uint16(b[2:4])
		if MessageType(ty) != MessageTypeGossipPush {
			t.Errorf("packet message type incorrect: expected 0x0030, received %x", ty)
		}
		si := b[12:44]
		if !bytes.Equal(si, mockSenderIdentity.ToBytes()) {
			t.Errorf("packet sender identity incorrect: expected %v, received %v", mockSenderIdentity, si)
		}
		ttl := b[44]
		if ttl != mockTTL {
			t.Errorf("packet TTL incorrect: expected %d, received %d", mockTTL, ttl)
		}
		// reserved 8 bits
		dt := binary.BigEndian.Uint16(b[46:48])
		if dt != mockDataType {
			t.Errorf("packet data type incorrect: expected %d, received %d", mockDataType, dt)
		}
		data := b[48 : 48+91]
		if !bytes.Equal(data, mockData) {
			t.Errorf("packet data incorrect: expected %v, received %v", mockData, data)
		}
		sig := b[139:]
		if !bytes.Equal(sig, mockSignature) {
			t.Errorf("packet signature incorrect: expected %v, received %v", mockSignature, sig)
		}
	})
}

// createMockSignature creates a 64 byte slice with each byte receiving a different value, which makes it more effective for comparisons.
func createMockSignature() []byte {
	mockSignature := make([]byte, SignatureSize)
	for ii := 0; ii < len(mockSignature); ii += 1 {
		mockSignature[ii] = uint8(ii)
	}
	return mockSignature
}
