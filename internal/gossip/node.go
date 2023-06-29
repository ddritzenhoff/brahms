package gossip

// Node represents a peer within the Gossip network.
type Node struct {
	Address string
}

// Identity represents the string representation of a Node.
func (n *Node) Identity() string {
	return n.Address
}
