package api

import (
	"bufio"
	"bytes"
	"errors"
	"testing"
)

func TestParsePacketHeader(t *testing.T) {
	t.Parallel()

	t.Run("correct packet header is parsed successfully", func(t *testing.T) {
		header, err := ParsePacketHeader([]byte{0x00, 0x10, 0x01, 0xF4})
		if err != nil {
			t.Error(err)
			return
		}
		if header.Size != 16 || header.Type != MessageTypeGossipAnnounce {
			t.Error("Header parsed wrong values", header)
			return
		}
	})

	t.Run("returns error on unsupported packet type", func(t *testing.T) {
		header, err := ParsePacketHeader([]byte{0x00, 0x10, 0x01, 0x90})
		if err == nil {
			t.Error("Invalid type 400 was accepted", header)
			return
		}
		if !errors.Is(err, ErrParsePacketHeaderInvalidType) {
			t.Error("Unexpected error type", err)
			return
		}
	})

	t.Run("returns error on invalid slice size", func(t *testing.T) {
		header, err := ParsePacketHeader([]byte{0x00, 0x10, 0x01, 0xF4, 0x00})
		if err == nil {
			t.Error("Invalid slice size was accepted", header)
			return
		}
		if !errors.Is(err, ErrParsePacketHeaderInvalidSize) {
			t.Error("Unexpected error type", err)
			return
		}

		header, err = ParsePacketHeader([]byte{0x00, 0x10, 0x01})
		if err == nil {
			t.Error("Invalid slice size was accepted", header)
			return
		}
		if !errors.Is(err, ErrParsePacketHeaderInvalidSize) {
			t.Error("Unexpected error type", err)
			return
		}
	})
}

type TestInfiniteReader struct {
	firstEmits []byte
}

func (r TestInfiniteReader) Read(b []byte) (int, error) {
	for n := range b {
		if n >= len(r.firstEmits) {
			b[n] = 0xFF
		} else {
			b[n] = r.firstEmits[n]
		}
	}
	return len(b), nil
}

func TestGossipAnnounce_Parse(t *testing.T) {
	t.Parallel()

	t.Run("correct packet is parsed successfully", func(t *testing.T) {
		reader := bufio.NewReader(bytes.NewReader([]byte{0x00, 0x0C, 0x01, 0xF4, 0x18, 0xFF, 0x04, 0xD2, 0x01, 0x23, 0x45, 0x67}))
		packet := GossipAnnounce{}
		err := packet.Parse(&PacketHeader{Size: 12, Type: MessageTypeGossipAnnounce}, reader)
		if err != nil {
			t.Error(err)
			return
		}
		if packet.TTL != 24 || packet.DataType != 1234 || !bytes.Equal(packet.Data, []byte{0x01, 0x23, 0x45, 0x67}) {
			t.Error("Packet parsed wrong values", packet)
			return
		}
	})

	t.Run("returns error on packet with invalid amount of bytes", func(t *testing.T) {
		reader := bufio.NewReader(bytes.NewReader([]byte{0x00, 0x0C, 0x01, 0xF4, 0x18, 0xFF, 0x04, 0xD2, 0x01, 0x23, 0x45}))
		packet := GossipAnnounce{}
		err := packet.Parse(&PacketHeader{Size: 12, Type: MessageTypeGossipAnnounce}, reader)
		if err == nil {
			t.Error("Invalid packet size was accepted", packet)
			return
		}
		if !errors.Is(err, ErrParsePacketInvalidSize) {
			t.Error("Unexpected error type", err)
		}

		reader = bufio.NewReader(bytes.NewReader([]byte{0x00, 0x0C, 0x01, 0xF4, 0x18, 0xFF, 0x04, 0xD2, 0x01, 0x23, 0x45, 0x67, 0xFF}))
		packet = GossipAnnounce{}
		err = packet.Parse(&PacketHeader{Size: 12, Type: MessageTypeGossipAnnounce}, reader)
		if err == nil {
			t.Error("Invalid packet size was accepted", packet)
			return
		}
		if !errors.Is(err, ErrParsePacketInvalidSize) {
			t.Error("Unexpected error type", err)
		}
	})

	t.Run("returns error on packet larger than 65535 bytes", func(t *testing.T) {
		reader := bufio.NewReader(TestInfiniteReader{firstEmits: []byte{0x00, 0x0C, 0x01, 0xF4, 0x18, 0xFF, 0x04, 0xD2, 0x01, 0x23, 0x45}})
		packet := GossipAnnounce{}
		err := packet.Parse(&PacketHeader{Size: 12, Type: MessageTypeGossipAnnounce}, reader)
		if err == nil {
			t.Error("Infinite packet size was accepted", packet)
			return
		}
		if !errors.Is(err, ErrParsePacketInvalidSize) {
			t.Error("Unexpected error type", err)
		}
	})
}

func TestGossipNotify_Parse(t *testing.T) {
	t.Parallel()
	t.Run("correct packet is parsed successfully", func(t *testing.T) {
		reader := bufio.NewReader(bytes.NewReader([]byte{0x00, 0x08, 0x01, 0xF5, 0xFF, 0xFF, 0x04, 0xD2}))
		packet := GossipNotify{}
		err := packet.Parse(&PacketHeader{Size: 8, Type: MessageTypeGossipNotify}, reader)
		if err != nil {
			t.Error(err)
			return
		}
		if packet.DataType != 1234 {
			t.Error("Packet parsed wrong values", packet)
			return
		}
	})

	t.Run("returns error on packet with invalid amount of bytes", func(t *testing.T) {
		reader := bufio.NewReader(bytes.NewReader([]byte{0x00, 0x08, 0x01, 0xF5, 0xFF, 0xFF, 0x04, 0xD2, 0xFF}))
		packet := GossipNotify{}
		err := packet.Parse(&PacketHeader{Size: 9, Type: MessageTypeGossipNotify}, reader)
		if err == nil {
			t.Error("Invalid packet size was accepted", packet)
			return
		}
		if !errors.Is(err, ErrParsePacketInvalidSize) {
			t.Error("Unexpected error type", err)
		}

		reader = bufio.NewReader(bytes.NewReader([]byte{0x00, 0x08, 0x01, 0xF5, 0xFF, 0xFF, 0x04}))
		packet = GossipNotify{}
		err = packet.Parse(&PacketHeader{Size: 8, Type: MessageTypeGossipNotify}, reader)
		if err == nil {
			t.Error("Invalid packet size was accepted", packet)
			return
		}
		if !errors.Is(err, ErrParsePacketInvalidSize) {
			t.Error("Unexpected error type", err)
		}
	})

}

func TestGossipValidation_Parse(t *testing.T) {
	t.Parallel()
	t.Run("correct packet is parsed successfully", func(t *testing.T) {
		reader := bufio.NewReader(bytes.NewReader([]byte{0x00, 0x08, 0x01, 0xF7, 0x04, 0xD2, 0x00, 0x01}))
		packet := GossipValidation{}
		err := packet.Parse(&PacketHeader{Size: 8, Type: MessageTypeGossipValidation}, reader)
		if err != nil {
			t.Error(err)
			return
		}
		if packet.MessageID != 1234 || packet.IsValid != true {
			t.Error("Packet parsed wrong values", packet)
			return
		}
	})

	t.Run("returns error on packet with invalid amount of bytes", func(t *testing.T) {
		reader := bufio.NewReader(bytes.NewReader([]byte{0x00, 0x08, 0x01, 0xF7, 0x04, 0xD2, 0x00, 0x01, 0xFF}))
		packet := GossipValidation{}
		err := packet.Parse(&PacketHeader{Size: 8, Type: MessageTypeGossipValidation}, reader)
		if err == nil {
			t.Error("Invalid packet size was accepted", packet)
			return
		}
		if !errors.Is(err, ErrParsePacketInvalidSize) {
			t.Error("Unexpected error type", err)
		}

		reader = bufio.NewReader(bytes.NewReader([]byte{0x00, 0x08, 0x01, 0xF7, 0x04, 0xD2, 0x00}))
		packet = GossipValidation{}
		err = packet.Parse(&PacketHeader{Size: 8, Type: MessageTypeGossipValidation}, reader)
		if err == nil {
			t.Error("Invalid packet size was accepted", packet)
			return
		}
		if !errors.Is(err, ErrParsePacketInvalidSize) {
			t.Error("Unexpected error type", err)
		}
	})
}
