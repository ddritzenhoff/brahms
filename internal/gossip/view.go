package gossip

import (
	"fmt"
	"math"
	"math/rand"
	"time"
)

// View represents a view within Brahms algorithm.
type View struct {
	alpha float64
	beta  float64
	gamma float64
	Nodes []Node
}

// NewView creates a new View object. View will set alpha, beta, and gamma to the recommended values of .45, .45, .10, respectively, if the `WithAlphaBetaGamma` option is not included.
func NewView(degree int, options ...Option) View {
	v := View{
		alpha: .45,
		beta:  .45,
		gamma: .1,
		Nodes: make([]Node, degree),
	}

	for _, option := range options {
		v = option(v)
	}
	return v
}

// Option represents a functional option for the View's 'constructor'.
type Option func(View) View

// WithAlphaBetaGamma sets the view's alpha, beta, and gamma values, respectively.
func WithAlphaBetaGamma(alpha float64, beta float64, gamma float64) Option {
	return func(v View) View {
		v.alpha = alpha
		v.beta = beta
		v.gamma = gamma
		return v
	}
}

// WithBootstrapNodes sets the view's Nodes parameter to a collection of 'bootstrap' nodes. Note that this overwrites any other nodes that may have been there before.
func WithBootstrapNodes(nodes []Node) Option {
	return func(v View) View {
		v.Nodes = nodes
		return v
	}
}

// L1Size represents the size of the ViewList.
func (v *View) L1Size() int {
	return len(v.Nodes)
}

// L1Alpha calculates L1*Alpha, which represents the number of pushes to be issued.
func (v *View) L1Alpha() int {
	return int(math.Round(v.alpha * float64(v.L1Size())))
}

// L1Beta calculates L1*Beta, which represents the number of pull requests to be issued.
func (v *View) L1Beta() int {
	return int(math.Round(v.beta * float64(v.L1Size())))
}

// RandomSubset returns a random subset of length n of the ViewList (i.e. L1) where 0 < n < |L1|.
func (v *View) RandomSubset(n int) ([]Node, error) {
	if n > v.L1Size() || n <= 0 {
		return nil, fmt.Errorf("RandomSubset: required size between 0 (non-inclusive) and |L1|")
	}
	r := rand.New(rand.NewSource(time.Now().Unix()))
	ret := make([]Node, n)
	perm := r.Perm(v.L1Size())
	for ii := 0; ii < n; ii += 1 {
		ret[ii] = v.Nodes[perm[ii]]
	}
	return ret, nil
}

// RandomPushSubset returns a random subset of length (alpha*|L1|) for pushes.
func (v *View) RandomPushSubset() ([]Node, error) {
	return v.RandomSubset(v.L1Alpha())
}

// RandomPullSubset returns a random subset of length (beta*|L1|) for pulls.
func (v *View) RandomPullSubset() ([]Node, error) {
	return v.RandomSubset(v.L1Beta())
}

// Bootstrap initializes the view list to a set of bootstrap nodes. Bootstrap should only be used during the 'initialization' phase of Brahm's.
func (v *View) Bootstrap(bootstrapNodes []Node) {
	v.Nodes = append(v.Nodes, bootstrapNodes...)
}
