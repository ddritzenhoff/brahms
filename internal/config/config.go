package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"go.uber.org/zap"
	"gopkg.in/ini.v1"
)

const RSAPrivateKey = "RSA PRIVATE KEY"

var defaultConfig = GossipConfig{
	Degree:       30,
	CacheSize:    50,
	ApiAddress:   "localhost:7001",
	HostkeysPath: "./hostkeys/",
	GossipAddress:       "localhost:7002",
	ChallengeDifficulty: 20,
	ChallengeMaxSolveMs: 300,
}

// GossipConfig represents all of the values needed for the functioning of the gossip protocol.
type GossipConfig struct {
	// Degree represents the size of L1.
	Degree     int
	CacheSize  int
	ApiAddress string
	// HostkeysPath represents the path to the folder in which all of the hostkeys exist. (i.e. Identity (file name) --> Public Key (file content))
	HostkeysPath string
	// PrivateKey represents the private key of the node.
	PrivateKey *rsa.PrivateKey
	GossipAddress       string
	ChallengeDifficulty int
	ChallengeMaxSolveMs int
}

// ReadConfig reads the values in from a .ini file through a specified path and returns a populated config.
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

	// empty quotations denote the root section.
	privKey := getPrivateKey(iniData.Section(""))

	return &GossipConfig{
		Degree:       getIntOrDefault(gossipSection.Key("degree"), defaultConfig.Degree, true),
		CacheSize:    getIntOrDefault(gossipSection.Key("cache_size"), defaultConfig.CacheSize, true),
		ApiAddress:   getStringOrDefault(gossipSection.Key("api_address"), defaultConfig.ApiAddress, false),
		HostkeysPath: getStringOrDefault(gossipSection.Key("hostkeys_path"), defaultConfig.HostkeysPath, true),
		PrivateKey:   privKey,
		GossipAddress:       getStringOrDefault(gossipSection.Key("gossip_address"), defaultConfig.GossipAddress, false),
		ChallengeDifficulty: getIntOrDefault(gossipSection.Key("challenge_difficulty"), defaultConfig.ChallengeDifficulty, false),
		ChallengeMaxSolveMs: getIntOrDefault(gossipSection.Key("challenge_max_solve_ms"), defaultConfig.ChallengeMaxSolveMs, false),
	}, nil
}

// getPrivateKey will either successfully retrieve the private key found at the value object of the hostkey key within the ini file, or it will panic.
func getPrivateKey(rootSection *ini.Section) *rsa.PrivateKey {
	hostkeyPath := rootSection.Key("hostkey").Value()
	if len(hostkeyPath) == 0 {
		panic("no hostkey path within the specified .ini file")
	}
	pemData, err := os.ReadFile(hostkeyPath)
	if err != nil {
		panic(fmt.Errorf("could not read file: filepath %s", hostkeyPath))
	}

	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			// no other keys/certificates in the PEM file, so break.
			break
		}
		if block.Type == RSAPrivateKey {
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				panic(errors.New("could not parse the private key"))
			}
			return key
		}

		pemData = rest
	}

	panic("Could not find the private key. Is it within the PEM file?")
}

// getIntOrDefault retrieves the int value saved within the config file or falls back to a default if no such key exists.
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

// getStringOrDefault retrieves teh string value saved within the config file or falls back to a default if no such key exists.
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
