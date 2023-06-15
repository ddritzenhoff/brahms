package main

import (
	"flag"
	"go.uber.org/zap"
	"gossiphers/internal/config"
	"os"
)

func main() {
	// Initialize global logger
	logger, _ := zap.NewProduction()
	zap.ReplaceGlobals(logger)

	cfgPath := flag.String("c", "config.ini", "Path to configuration file")
	flag.Parse()

	cfg, err := config.ReadConfig(*cfgPath)
	if err != nil {
		os.Exit(1)
	}

	zap.L().Debug("Configuration read", zap.Any("config", cfg))
}
