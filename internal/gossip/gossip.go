package gossip

import "gossiphers/internal/config"

type Gossip struct {
	sg    SamplerGroup
	view  []Node
	cfg   *config.GossipConfig
	alpha float32
	beta  float32
	gamma float32
}

func (g *Gossip) Init(cfg *config.GossipConfig) error {
	g.alpha = float32(cfg.WeightPush) / float32(cfg.WeightPush+cfg.WeightPull+cfg.WeightHistory)
	g.beta = float32(cfg.WeightPull) / float32(cfg.WeightPush+cfg.WeightPull+cfg.WeightHistory)
	g.gamma = float32(cfg.WeightHistory) / float32(cfg.WeightPush+cfg.WeightPull+cfg.WeightHistory)

	g.view = make([]Node, cfg.Degree)
	err := g.sg.init(cfg.Degree)
	if err != nil {
		return err
	}

	var bootstrapNodes []Node
	for i, addr := range cfg.BootstrapNodes {
		node := Node{Address: addr}
		bootstrapNodes = append(bootstrapNodes, node)
		g.view[i] = node
	}
	g.sg.update(bootstrapNodes)

	return nil
}

func (g *Gossip) Start() error {
	server, err := startServer(g.cfg, g)
	if err != nil {
		return err
	}

	// TODO: implement gossip rounds with time.tick,
	return nil
}
