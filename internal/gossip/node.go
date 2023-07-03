package gossip

type Node struct {
	Address string
}

func (n *Node) Identity() string {
	return n.Address
}
