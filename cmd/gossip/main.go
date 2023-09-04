package main

import (
	"flag"
	"go.uber.org/zap"
	"gossiphers/internal/config"
	"gossiphers/internal/gossip"
)

func main() {
	// Initialize global logger
	logger, _ := zap.NewProduction()
	zap.ReplaceGlobals(logger)

	cfgPath := flag.String("c", "config.ini", "Path to configuration file")
	flag.Parse()

	cfg, err := config.ReadConfig(*cfgPath)
	if err != nil {
		zap.L().Fatal("Error reading configuration", zap.Error(err))
	}

	zap.L().Debug("Configuration read", zap.Any("config", cfg))
	gsp, err := gossip.NewGossip(cfg)
	if err != nil {
		zap.L().Fatal("Error creating gossip", zap.Error(err))
	}
	err = gsp.Start()
	if err != nil {
		zap.L().Fatal("Error during gossip rounds", zap.Error(err))
	}
}
