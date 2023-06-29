package config

import (
	"fmt"
	"math"
	"strings"
	"time"

	"go.uber.org/zap"
	"gopkg.in/ini.v1"
)

const float64EqualityThreshold = 1e-9

var defaultConfig = GossipConfig{
	Degree:           30,
	L2Size:           30,
	CacheSize:        50,
	WeightPush:       45,
	WeightPull:       45,
	WeightHistory:    10,
	ConnWriteTimeout: time.Second * 5, // TODO (ddritzenhoff) Totally arbitrary. Maybe think of a better value.
	Difficulty:       10,              // TODO (ddritzenhoff) Totally arbitrary. Maybe think of a better value.
	P2PAddress:       "localhost:6001",
	ApiAddress:       "localhost:7001",
	BootstrapNodes:   []string{},
}

type GossipConfig struct {
	// Degree represents the size of L1.
	Degree           int
	L2Size           int
	CacheSize        int
	WeightPush       int
	WeightPull       int
	WeightHistory    int
	ConnWriteTimeout time.Duration
	Difficulty       int
	P2PAddress       string
	ApiAddress       string
	BootstrapNodes   []string
}

// AlphaBetaGamma calculates alpha, beta, and gamma values from the config weights.
func (gc *GossipConfig) AlphaBetaGamma() (alpha float64, beta float64, gamma float64, err error) {
	denom := gc.WeightPush + gc.WeightPull + gc.WeightHistory
	alpha = float64(gc.WeightPush) / float64(denom)
	beta = float64(gc.WeightPull) / float64(denom)
	gamma = float64(gc.WeightHistory) / float64(denom)

	if alpha >= 1.0 || alpha <= 0.0 || beta >= 1.0 || beta <= 0.0 || gamma >= 1.0 || gamma <= 0.0 {
		err = fmt.Errorf("AlphaBetaGamma: alpha, beta, and gamma must have values between (0, 1) -- alpha=%.3f, beta=%.3f, gamma=%.3f", alpha, beta, gamma)
		return
	}

	if !almostEqual(alpha+beta+gamma, 1.0) {
		err = fmt.Errorf("NewView: alpha + beta + gamma must equal 1.0 -- alpha=%.3f, beta=%.3f, gamma=%.3f", alpha, beta, gamma)
		return
	}

	return
}

// almostEqual checks whether two floats are equal within a certain tolerance
func almostEqual(a, b float64) bool {
	return math.Abs(a-b) <= float64EqualityThreshold
}

func ReadConfig(path string) (*GossipConfig, error) {
	iniData, err := ini.Load(path)
	if err != nil {
		zap.L().Error("Could not parse provided configuration.", zap.String("path", path), zap.Error(err))
		return nil, err
	}

	gossipSection := iniData.Section("gossip")
	if gossipSection == nil {
		zap.L().Warn("Provided configuration does not contain a gossip section, falling back to default options.")
		return &defaultConfig, nil
	}

	var bootstrapNodes []string
	bootstrapNodesString := getStringOrDefault(gossipSection.Key("bootstrap_nodes"), strings.Join(defaultConfig.BootstrapNodes, ","), true)
	if len(bootstrapNodesString) > 0 {
		bootstrapNodes = strings.Split(bootstrapNodesString, ",")
	}

	weightPush := getIntOrDefault(gossipSection.Key("weight_push"), defaultConfig.CacheSize, true)
	weightPull := getIntOrDefault(gossipSection.Key("weight_pull"), defaultConfig.CacheSize, true)
	weightHistory := getIntOrDefault(gossipSection.Key("weight_history"), defaultConfig.CacheSize, true)
	if weightPush <= 0 || weightPull <= 0 || weightHistory <= 0 {
		return nil, fmt.Errorf("all weights must be greater than 0 -- weightPush:%d, weightPull:%d, weightHistory:%d", weightPush, weightPull, weightHistory)
	}

	connWriteTimeout := time.Duration(getTimeDurationInSecOrDefault(gossipSection.Key("conn_write_timeout_sec"), defaultConfig.ConnWriteTimeout, true)) * time.Second

	difficulty := getIntOrDefault(gossipSection.Key("difficulty"), defaultConfig.Difficulty, true)
	if difficulty <= 0 {
		return nil, fmt.Errorf("difficulty must be 0 or greater: %d", difficulty)
	}

	return &GossipConfig{
		Degree:           getIntOrDefault(gossipSection.Key("degree"), defaultConfig.Degree, true),
		L2Size:           getIntOrDefault(gossipSection.Key("l2_size"), defaultConfig.L2Size, true),
		CacheSize:        getIntOrDefault(gossipSection.Key("cache_size"), defaultConfig.CacheSize, true),
		WeightPush:       weightPush,
		WeightPull:       weightPull,
		WeightHistory:    weightHistory,
		ConnWriteTimeout: connWriteTimeout,
		Difficulty:       difficulty,
		P2PAddress:       getStringOrDefault(gossipSection.Key("p2p_address"), defaultConfig.P2PAddress, false),
		ApiAddress:       getStringOrDefault(gossipSection.Key("api_address"), defaultConfig.ApiAddress, false),
		BootstrapNodes:   bootstrapNodes,
	}, nil
}

func getTimeDurationInSecOrDefault(key *ini.Key, fallback time.Duration, warnMissing bool) time.Duration {
	// TODO (ddritzenhoff) Consider using library to get time duration instead of int.
	v, err := key.Int()
	if err != nil {
		if warnMissing {
			zap.L().Warn("Configuration value missing, falling back to default", zap.String("key", key.Name()), zap.Duration("default", fallback))
		}
		return fallback
	}
	return time.Duration(v) * time.Second
}

func getIntOrDefault(key *ini.Key, fallback int, warnMissing bool) int {
	val, err := key.Int()
	if err == nil {
		return val
	}
	if warnMissing {
		zap.L().Warn("Configuration value missing, falling back to default", zap.String("key", key.Name()), zap.Int("default", fallback))
	}
	return fallback
}

func getStringOrDefault(key *ini.Key, fallback string, warnMissing bool) string {
	val := key.Value()
	if len(val) != 0 {
		return val
	}
	if warnMissing {
		zap.L().Warn("Configuration value missing, falling back to default", zap.String("key", key.Name()), zap.String("default", fallback))
	}
	return fallback
}
