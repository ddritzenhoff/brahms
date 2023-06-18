package config

import (
	"go.uber.org/zap"
	"gopkg.in/ini.v1"
	"strings"
)

type GossipConfig struct {
	Degree         int
	CacheSize      int
	WeightPush     int
	WeightPull     int
	WeightHistory  int
	P2PAddress     string
	ApiAddress     string
	BootstrapNodes []string
}

var defaultConfig = GossipConfig{
	Degree:         30,
	CacheSize:      50,
	WeightPush:     45,
	WeightPull:     45,
	WeightHistory:  10,
	P2PAddress:     "localhost:6001",
	ApiAddress:     "localhost:7001",
	BootstrapNodes: []string{},
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
	bootstrapNodesString := getStringOrDefault(gossipSection.Key("bootstrap_nodes"), strings.Join(defaultConfig.BootstrapNodes, ","), false)
	if len(bootstrapNodesString) > 0 {
		bootstrapNodes = strings.Split(bootstrapNodesString, ",")
	}

	return &GossipConfig{
		Degree:         getIntOrDefault(gossipSection.Key("degree"), defaultConfig.Degree, true),
		CacheSize:      getIntOrDefault(gossipSection.Key("cache_size"), defaultConfig.CacheSize, true),
		WeightPush:     getIntOrDefault(gossipSection.Key("weight_push"), defaultConfig.CacheSize, false),
		WeightPull:     getIntOrDefault(gossipSection.Key("weight_pull"), defaultConfig.CacheSize, false),
		WeightHistory:  getIntOrDefault(gossipSection.Key("weight_history"), defaultConfig.CacheSize, false),
		P2PAddress:     getStringOrDefault(gossipSection.Key("p2p_address"), defaultConfig.P2PAddress, false),
		ApiAddress:     getStringOrDefault(gossipSection.Key("api_address"), defaultConfig.ApiAddress, false),
		BootstrapNodes: bootstrapNodes,
	}, nil
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
