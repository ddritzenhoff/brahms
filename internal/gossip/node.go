package gossip

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// IdentitySize represents the size of the Node's Identity attribute, which is the 32 byte result of the SHA256 hash of the Node's respective public key.
const IdentitySize int = sha256.Size // 32

// Identity represents a SHA256 hash of a public key.
type Identity string

// NewIdentity generates a new Identity given a string if it is of the correct size.
func NewIdentity(hash []byte) (*Identity, error) {
	if len(hash) != IdentitySize {
		return nil, fmt.Errorf("id of wrong size: expected %d, received %d", sha256.Size, len(hash))
	}
	id := Identity(hash[:])
	return &id, nil
}

// String represents the Identity as an uppercase hex-encoded string.
func (id Identity) String() string {
	return hex.EncodeToString([]byte(id))
}

// Node represents a peer within the Gossip network.
type Node struct {
	Identity Identity
	Address  string
}

// NewNode returns a new instance of Node.
func NewNode(identity []byte, address string) (*Node, error) {
	id, err := NewIdentity(identity)
	if err != nil {
		return nil, err
	}

	return &Node{
		Identity: *id,
		Address:  address,
	}, nil
}

// String returns the string representation of a node.
func (n *Node) String() string {
	return n.Identity.String() + n.Address
}
