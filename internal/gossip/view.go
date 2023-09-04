package gossip

import (
	"sync"
)

// View represents a view within Brahms algorithm.
type View struct {
	nodes []Node
	mu    sync.Mutex
}

// NewView creates a new View object with an empty slice of Nodes unless `WithBootstrapNodes` is additionally passed in.
func NewView(options ...Option) (*View, error) {
	v := &View{
		nodes: make([]Node, 0, 30),
	}

	for _, option := range options {
		err := option(v)
		if err != nil {
			return nil, err
		}
	}
	return v, nil
}

// Option represents a functional option for the View's 'constructor'.
type Option func(*View) error

// WithBootstrapNodes sets the view's Nodes parameter to a collection of 'bootstrap' nodes. Note that this overwrites any other nodes that may have been there before.
func WithBootstrapNodes(nodes []Node) Option {
	return func(v *View) error {
		v.nodes = nodes
		return nil
	}
}

// Clear resets the view back to 0 nodes.
func (v *View) Clear() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.nodes = make([]Node, 0, 30)
}

// Append adds a node to the view.
func (v *View) Append(n Node) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.nodes = append(v.nodes, n)
}

// GetAll returns a copy of the nodes within the View.
func (v *View) GetAll() []Node {
	v.mu.Lock()
	defer v.mu.Unlock()
	copySlice := make([]Node, len(v.nodes))
	copy(copySlice, v.nodes)
	return copySlice
}
