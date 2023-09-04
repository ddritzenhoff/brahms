package gossip

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"go.uber.org/zap"
)

// IdentitySize represents the size of the Node's Identity attribute, which is the 32 byte result of the SHA256 hash of the Node's respective public key.
const IdentitySize int = sha256.Size // 32

// TODO (ddritzenhoff) replace []byte with Identity and refactor existing code to work with the change.
// Node represents a peer within the Gossip network.
type Node struct {
	Identity []byte // 32
	Address  string
}

// NewNode returns a new instance of Node.
func NewNode(Identity []byte, Address string) (*Node, error) {
	if len(Identity) != IdentitySize {
		zap.L().Error("Identity is not of the correct length", zap.Int("len", len(Identity)))
		return nil, fmt.Errorf("identity is not of the correct length: expected %d, received %d", IdentitySize, len(Identity))
	}

	return &Node{
		Identity: Identity,
		Address:  Address,
	}, nil
}

// String returns the string representation of a node.
func (n *Node) String() string {
	return hex.EncodeToString(n.Identity) + n.Address
}
