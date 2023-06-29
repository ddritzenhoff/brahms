package gossip

import (
	"context"
	"gossiphers/internal/challenge"
	"gossiphers/internal/config"
	"math"
	"time"
)

// TODO (ddritzenhoff) figure out how to use logging and consider adding it throughout.

// Gossip represents the data structures for the Brahms algorithm.
type Gossip struct {
	self     Node
	sg       SamplerGroup
	view     View
	PushList []Node
	PullList []Node
	cfg      *config.GossipConfig
}

// NewGossip creates a new Gossip instance.
func NewGossip(selfNodeAddr string, cfg *config.GossipConfig) (*Gossip, error) {
	// Initiate each sampler (.init).
	var sg SamplerGroup
	err := sg.Init(cfg.Degree)
	if err != nil {
		return nil, err
	}

	// Give each sampler an element (.next).
	var bootstrapNodes []Node
	for _, addr := range cfg.BootstrapNodes {
		node := Node{Address: addr}
		bootstrapNodes = append(bootstrapNodes, node)
	}
	sg.Update(bootstrapNodes)

	alpha, beta, gamma, err := cfg.AlphaBetaGamma()
	if err != nil {
		return nil, err
	}
	view := NewView(cfg.Degree, WithAlphaBetaGamma(alpha, beta, gamma), WithBootstrapNodes(bootstrapNodes))

	self := Node{Address: selfNodeAddr}
	pushListSize := int(math.Round(float64(cfg.Degree) * alpha))
	pullListSize := int(math.Round(float64(cfg.Degree) * beta))
	return &Gossip{
		self:     self,
		sg:       sg,
		view:     view,
		PushList: make([]Node, pushListSize),
		PullList: make([]Node, pullListSize),
		cfg:      cfg,
	}, nil
}

func (g *Gossip) issuePushRequests(timeoutDur time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDur)
	defer cancel()

	// pushNodes, err := g.view.RandomPushSubset()
	// if err != nil {
	// 	return err
	// }
	// for _, n := range pushNodes {
	// }

	<-ctx.Done()
	return nil
}

func (g *Gossip) issuePullRequests(timeoutDur time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDur)
	defer cancel()

	// pullNodes, err := g.view.RandomPullSubset()
	// if err != nil {
	// 	return err
	// }
	// for _, n := range pullNodes {
	// 	err = g.self.PullRequest(ctx, n)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	<-ctx.Done()
	return nil
}

// TODO (ddritzenhoff) figure out what to do with challenger.
func (g *Gossip) Start(c challenge.Challenger) error {
	pushes := make(chan Node, g.view.L1Alpha())
	pulls := make(chan View, g.view.L1Beta())

	s := NewServer(pushes, pulls, g, c)
	err := s.Open()
	if err != nil {
		return err
	}

	// note that all ids are streamed to the samplers. This is how the samplers update themselves

	// TODO (ddritzenhoff) can add a NSE (network size estimator) query here to update the push, pull, and view sizes.
	// empty push and pull lists
	g.PushList = make([]Node, len(g.PushList))
	g.PullList = make([]Node, len(g.PullList))

	timeoutDurPush := time.Second * 5
	go g.issuePushRequests(timeoutDurPush)
	timeoutDurPull := time.Second * 5
	go g.issuePullRequests(timeoutDurPull)

	// send pull requests to (beta * L1) nodes randomly selected from the view

	// listen to all pushes coming into this node.

	// update View with new values only if {pushList < (alpha * L1) and |pushList|>0 and |pullList|>0}
	// 	- update View with randomly chosen (alpha * L1) pushed ids.
	// 	- update View with randomly chosen (beta * L1) pulled ids.
	// update samplers with new values

	// TODO: implement gossip rounds with time.tick,
	return nil
}
