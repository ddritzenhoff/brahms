package config

import (
	"go.uber.org/zap"
	"gopkg.in/ini.v1"
)

type GossipConfig struct {
	Degree    int
	CacheSize int
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
		return &GossipConfig{
			Degree:    30,
			CacheSize: 50,
		}, nil
	}

	degree := getIntOrDefault(gossipSection.Key("degree"), 30, true)
	cacheSize := getIntOrDefault(gossipSection.Key("cache_size"), 50, true)

	return &GossipConfig{
		Degree:    degree,
		CacheSize: cacheSize,
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
