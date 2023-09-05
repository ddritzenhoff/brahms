package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"

	"go.uber.org/zap"
	"gopkg.in/ini.v1"
)

// RSAPrivateKey represents the format the PEM expects within the preamble.
const (
	RSAPrivateKey            = "RSA PRIVATE KEY"
	float64EqualityThreshold = 1e-3
)

var defaultConfig = GossipConfig{
	ViewSize:    30,
	SamplerSize: 30,
	Alpha:       .45,
	Beta:        .45,
	Gamma:       .1,
	/* BootstrapNodesStr doesn't have a default value */
	// A value of 8 suggests ~8 seconds between health checks.
	RoundsBetweenPings:  8,
	ApiAddress:          "localhost:7001",
	HostkeysPath:        "./hostkeys/",
	GossipAddress:       "localhost:7002",
	ChallengeDifficulty: 19,
	ChallengeMaxSolveMs: 300,
	weightPull:          45,
	weightPush:          45,
	weightHistory:       10,
}

// GossipConfig represents all of the values needed for the functioning of the gossip protocol.
type GossipConfig struct {
	ViewSize    int
	SamplerSize int
	Alpha       float64
	Beta        float64
	Gamma       float64
	ApiAddress  string
	// BootstrapNodesStr is a list of node components in the following form --> nodes = <addr1>,<id1>|<addr2>,<id2>|...|<addrn>,<idn>|
	BootstrapNodesStr string
	// RoundsBetweenPings represents the number of rounds in between sending out health checks to peers existing within all of the samplers to see whether they are still alive.
	RoundsBetweenPings int
	// HostkeysPath represents the path to the folder in which all of the hostkeys exist. (i.e. Identity (file name) --> Public Key (file content))
	HostkeysPath string
	// PrivateKey represents the private key of the node.
	PrivateKey          *rsa.PrivateKey
	GossipAddress       string
	ChallengeDifficulty int
	ChallengeMaxSolveMs int
	weightPull          int
	weightPush          int
	weightHistory       int
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

	alpha, beta, gamma, err := alphaBetaGamma(gossipSection)
	if err != nil {
		zap.L().Error("Could not retrieve alpha, beta, and gamma values", zap.Error(err))
		return nil, err
	}

	// empty quotations denote the root section.
	privKey := getPrivateKey(iniData.Section(""))

	return &GossipConfig{
		ViewSize:            getIntOrDefault(gossipSection.Key("degree"), defaultConfig.ViewSize, true),
		SamplerSize:         getIntOrDefault(gossipSection.Key("l2"), defaultConfig.SamplerSize, true),
		Alpha:               alpha,
		Beta:                beta,
		Gamma:               gamma,
		BootstrapNodesStr:   gossipSection.Key("bootstrap_nodes").Value(),
		RoundsBetweenPings:  getIntOrDefault(gossipSection.Key("rounds_between_pings"), defaultConfig.RoundsBetweenPings, false),
		ApiAddress:          getStringOrDefault(gossipSection.Key("api_address"), defaultConfig.ApiAddress, false),
		HostkeysPath:        getStringOrDefault(gossipSection.Key("hostkeys_path"), defaultConfig.HostkeysPath, true),
		PrivateKey:          privKey,
		GossipAddress:       getStringOrDefault(gossipSection.Key("gossip_address"), defaultConfig.GossipAddress, false),
		ChallengeDifficulty: getIntOrDefault(gossipSection.Key("challenge_difficulty"), defaultConfig.ChallengeDifficulty, false),
		ChallengeMaxSolveMs: getIntOrDefault(gossipSection.Key("challenge_max_solve_ms"), defaultConfig.ChallengeMaxSolveMs, false),
	}, nil
}

// alphaBetaGamma retrieves the alpha, beta, and gamma values from the config. Note that weightPush, weightPull, and weightHistory must add up to 100.
func alphaBetaGamma(gossipSection *ini.Section) (alpha float64, beta float64, gamma float64, err error) {
	weightPush := getIntOrDefault(gossipSection.Key("weight_push"), defaultConfig.weightPush, true)
	weightPull := getIntOrDefault(gossipSection.Key("weight_pull"), defaultConfig.weightPull, true)
	weightHistory := getIntOrDefault(gossipSection.Key("weight_history"), defaultConfig.weightHistory, true)
	if weightPush <= 0 || weightPull <= 0 || weightHistory <= 0 {
		err = fmt.Errorf("all weights must be greater than 0 -- weightPush:%d, weightPull:%d, weightHistory:%d", weightPush, weightPull, weightHistory)
		return
	}

	if weightPush+weightPull+weightHistory-100 != 0 {
		err = fmt.Errorf("weightPush (%d), weightPull (%d), and weightHistory (%d) must add up to 100", weightPush, weightPull, weightHistory)
		return
	}
	alpha = float64(weightPush) / 100.0
	beta = float64(weightPull) / 100.0
	gamma = float64(weightHistory) / 100.0

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
