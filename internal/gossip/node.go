package gossip

type Node struct {
	Address string
}

func (n *Node) Identity() string {
	return n.Address
}

func (n *Node) Probe() error {
	// PING --timeout--> receive PONG
	return nil
}

func (n *Node) Push(pushNodes []*Node) error {
	// PUSH REQUEST --timeout--> receive PUSH CHALLENGE --solve challenge--> PUSH
	return nil
}

func (n *Node) Pull() ([]Node, error) {
	// PULL REQUEST --timeout--> receive PULL RESPONSE
	return nil, nil
}
