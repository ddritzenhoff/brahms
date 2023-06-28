package api

import (
	"bytes"
	"testing"
)

func TestGossipNotification_ToBytes(t *testing.T) {
	t.Run("check correctness of bytes", func(t *testing.T) {
		packet := GossipNotification{
			PacketHeader: PacketHeader{
				Size: 12,
				Type: MessageTypeGossipNotification,
			},
			MessageID: 123,
			DataType:  321,
			Data:      []byte{0x01, 0x02, 0x03, 0x04},
		}
		packetBytes := packet.ToBytes()
		if !bytes.Equal(packetBytes, []byte{0x00, 0x0C, 0x01, 0xF6, 0x00, 0x7B, 0x01, 0x41, 0x01, 0x02, 0x03, 0x04}) {
			t.Error("Generated packet bytes not correct", packetBytes)
		}
	})
}
