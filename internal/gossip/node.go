package gossip

import (
	"crypto/sha256"
	"errors"

	"go.uber.org/zap"
)

// IdentitySize represents the size of the Node's Identity attribute, which is the 32 byte result of the SHA256 hash of the Node's respective public key.
const IdentitySize int = sha256.Size

// Node represents a peer within the Gossip network.
type Node struct {
	Identity []byte
	Address  string
}

func NewNode(Identity []byte, Address string) (*Node, error) {
	if len(Identity) != IdentitySize {
		zap.L().Error("Identity is not of the correct length", zap.Int("len", len(Identity)))
		return nil, errors.New("Identity is not of the correct length")
	}

	return &Node{
		Identity: Identity,
		Address:  Address,
	}, nil
}
