package gossip

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"gossiphers/internal/api"
	"gossiphers/internal/config"
	"math"
	"math/big"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Gossip represents the gossip protocol.
type Gossip struct {
	cfg          *config.GossipConfig
	apiServer    *api.Server
	gossipServer *Server
	pushView     *View
	pushNodes    chan Node
	pullView     *View
	pullNodes    chan Node
	mainView     *View
	samplerGroup *SamplerGroup
}

// NewGossip returns a new instance of Gossip
func NewGossip(cfg *config.GossipConfig) (*Gossip, error) {
	apiServer := api.NewServer(cfg)

	pushNodes := make(chan Node)
	pullNodes := make(chan Node)
	gCrypto, err := NewCrypto(cfg)
	if err != nil {
		zap.L().Error("Error initializing crypto")
		return nil, err
	}
	gossipServer, err := NewServer(cfg, pushNodes, pullNodes, gCrypto, apiServer)
	if err != nil {
		zap.L().Error("Error initializing gossip server")
		return nil, err
	}

	pushView := NewView()
	pullView := NewView()

	samplerGroup, err := NewSamplerGroup(cfg.SamplerSize)
	if err != nil {
		return nil, err
	}

	bootstrapNodes, err := parseBootstrapNodesStr(cfg.BootstrapNodesStr)
	if err != nil {
		return nil, err
	}

	mainView := NewView(WithBootstrapNodes(bootstrapNodes))

	samplerGroup.Update(bootstrapNodes)

	return &Gossip{
		cfg:          cfg,
		apiServer:    apiServer,
		gossipServer: gossipServer,
		pushView:     pushView,
		pushNodes:    pushNodes,
		pullView:     pullView,
		pullNodes:    pullNodes,
		mainView:     mainView,
		samplerGroup: samplerGroup,
	}, nil
}

// Start starts the gossip protocol.
func (g *Gossip) Start() error {
	round := 1
	zap.L().Info("starting the gossip protocol", zap.Int("round", round))

	// Start API server
	err := g.apiServer.Start()
	if err != nil {
		return err
	}

	// Start Gossip server
	err = g.gossipServer.Start()
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case node := <-g.pullNodes:
				g.pullView.Append(node)
			}
		}
	}()

	go func() {
		for {
			select {
			case node := <-g.pushNodes:
				g.pushView.Append(node)
			}
		}
	}()

	for {
		g.gossipServer.ResetPeerStates()
		g.pushView.Clear()
		g.pullView.Clear()
		mainViewNodes := g.mainView.GetAll()
		g.gossipServer.UpdatePullResponseNodes(mainViewNodes)

		// periodically health-check (ping) nodes within the samplers.
		var samplerWaitGroup sync.WaitGroup
		alreadySampled := map[string]struct{}{}
		if round%g.cfg.RoundsBetweenPings == 0 {
			for _, sampler := range g.samplerGroup.samplers {
				if sampler.Sample() == nil {
					continue
				}
				if _, wasSampled := alreadySampled[sampler.Sample().String()]; wasSampled {
					continue
				}
				alreadySampled[sampler.Sample().String()] = struct{}{}
				samplerWaitGroup.Add(1)
				movedSampler := sampler
				go func() {
					defer samplerWaitGroup.Done()
					if !g.gossipServer.Ping(movedSampler.Sample(), time.Millisecond*500) {
						zap.L().Info("Sampler node offline, reinitializing sampler...", zap.String("node", movedSampler.Sample().String()))
						err = movedSampler.Init()
						if err != nil {
							zap.L().Error("Error reinitializing sampler", zap.Error(err))
						}
					}
				}()
			}
		}

		pushToNodes, err := randSubset(mainViewNodes, g.AlphaL1())
		if err != nil {
			return err
		}
		for _, node := range pushToNodes {
			g.gossipServer.SendPushRequest(node)
		}

		pullFromNodes, err := randSubset(mainViewNodes, g.BetaL1())
		if err != nil {
			return err
		}
		for _, node := range pullFromNodes {
			g.gossipServer.SendPullRequest(node)
		}

		// pause execution for a second while waiting for responses.
		time.Sleep(1 * time.Second)

		pushViewNodes := g.pushView.GetAll()
		pullViewNodes := g.pullView.GetAll()
		if len(pushViewNodes) <= g.AlphaL1() && len(pushViewNodes) > 0 && (len(pullViewNodes) > 0 || len(pullFromNodes) == 0) {
			randPushViewNodesSubset, err := randSubset(pushViewNodes, g.AlphaL1())
			if err != nil {
				return err
			}
			randPullViewNodesSubset, err := randSubset(pullViewNodes, g.BetaL1())
			if err != nil {
				return err
			}
			randSamplerNodesSubset, err := g.samplerGroup.RandomNodeSubset(g.GammaL1())
			if err != nil {
				return err
			}

			nodes := g.trimDuplicates(randPullViewNodesSubset, randPushViewNodesSubset, randSamplerNodesSubset)
			g.mainView = NewView(WithBootstrapNodes(nodes))
		}
		samplerWaitGroup.Wait()
		g.samplerGroup.Update(pushViewNodes)
		g.samplerGroup.Update(pullViewNodes)

		// increment round
		round++
		zap.L().Info("new round starting", zap.Int("round", round), zap.Int("current_view_size", g.mainView.NodeCount()))
	}
}

// AlphaL1 represents the number of push requests to be initiated.
func (g *Gossip) AlphaL1() int {
	return int(math.Round(float64(g.cfg.ViewSize) * g.cfg.Alpha))
}

// BetaL1 represents the pull requests to destinations that will be randomly selected from the view.
func (g *Gossip) BetaL1() int {
	return int(math.Round(float64(g.cfg.ViewSize) * g.cfg.Beta))
}

// GammaL1 represents the number of history samples (nodes sampled from the sampler group) to be used in the next view.
func (g *Gossip) GammaL1() int {
	return int(math.Round(float64(g.cfg.ViewSize) * g.cfg.Gamma))
}

// trimDuplicates combines slices of nodes while trimming the duplicates.
func (g *Gossip) trimDuplicates(listNodes ...[]*Node) []Node {
	unique := make(map[string]bool)
	result := make([]Node, 0)
	for _, nodes := range listNodes {
		for _, node := range nodes {
			if !unique[node.String()] {
				unique[node.String()] = true
				result = append(result, *node)
			}
		}
	}
	return result
}

// parseNodes takes a string of the form <id1>,<addr1>|<id2>,<addr2>|...|<idn>,<addrn>| and parses it into a slice of nodes.
func parseBootstrapNodesStr(nodesStr string) ([]Node, error) {
	nodePairs := strings.Split(nodesStr, "|")
	var nodes []Node
	for _, nodePair := range nodePairs {
		// Skip empty lines
		if nodePair == "" {
			continue
		}
		parts := strings.Split(nodePair, ",")
		if len(parts) != 2 {
			return nil, fmt.Errorf("node list encoding incorrect: not able to identify the identity and address of the node: received %s and decoded it into %v", nodePair, parts)
		}
		identity, err := hex.DecodeString(parts[0])
		if err != nil {
			return nil, err
		}
		node, err := NewNode(identity, parts[1])
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, *node)
	}
	return nodes, nil
}

// RandomSubset returns a random subset of up to length n of the nodes. If n is greater then len(nodes), only a random subset of len(nodes) will be returned.
func randSubset(nodes []Node, n int) ([]*Node, error) {
	if n == 0 {
		return nil, nil
	} else if n > len(nodes) {
		return randSubset(nodes, len(nodes))
	} else if n < 0 {
		return nil, fmt.Errorf("n cannot be negative: received %d", n)
	}

	copySlice := make([]*Node, 0)
	for ii := 0; ii < len(nodes); ii++ {
		copySlice = append(copySlice, &nodes[ii])
	}

	for i := 0; i < len(copySlice); i++ {
		// Generate a random index between 0 and i (inclusive)
		bigJ, err := rand.Int(rand.Reader, big.NewInt(int64(len(copySlice))))
		if err != nil {
			return nil, err
		}
		if !bigJ.IsInt64() {
			return nil, fmt.Errorf("j is not of type int64: %s", bigJ.String())
		}
		j := bigJ.Int64()

		// Swap the elements at i and j
		copySlice[i], copySlice[j] = copySlice[j], copySlice[i]
	}
	return copySlice[:n], nil
}
