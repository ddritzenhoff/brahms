package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	dockerClient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/go-connections/nat"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const (
	dockerNetworkName          = "gossip-test-network"
	testCertsDir               = "test-data" + string(os.PathSeparator) + "testcerts"
	testConfigPath             = "test-data" + string(os.PathSeparator) + "test-config.ini"
	bootstrappedTestConfigPath = "test-data" + string(os.PathSeparator) + "test-config-bootstrap.ini"
	rsaKeySize                 = 4096
	dockerImageName            = "gossiphers:test"
)

func main() {
	startCmd := flag.NewFlagSet("start", flag.ExitOnError)
	numNodes := startCmd.Int("n", 10, "Number of gossip containers to spawn")

	if len(os.Args) < 2 {
		fmt.Println("Usage: test-gossip [start,stop]")
		os.Exit(1)
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalln(err)
	}
	if filepath.Base(cwd) != "e2e-test" {
		log.Fatalln("this tool should be executed from the e2e-test directory")
	}

	switch strings.ToLower(os.Args[1]) {
	case "start":
		err := startCmd.Parse(os.Args[2:])
		if err != nil {
			return
		}
		runStartCommand(*numNodes)
	case "stop":
		runStopCommand()
	default:
		fmt.Println("expected 'start' or 'stop' subcommand")
		os.Exit(1)
	}

}

type dockerBuildMessage struct {
	Stream string `json:"stream"`
}

func runStartCommand(numNodes int) {
	ctx := context.Background()
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Starting docker client...")
	cli, err := dockerClient.NewClientWithOpts(dockerClient.FromEnv, dockerClient.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Deleting old versions of the test image...")
	imgList, err := cli.ImageList(ctx, types.ImageListOptions{All: true})
	if err != nil {
		log.Fatalln(err)
	}
	for _, img := range imgList {
		for _, tag := range img.RepoTags {
			if tag == dockerImageName {
				_, err = cli.ImageRemove(ctx, img.ID, types.ImageRemoveOptions{})
			}
		}
	}

	log.Println("Building docker image...")
	tar, err := archive.TarWithOptions(filepath.Dir(cwd), &archive.TarOptions{ExcludePatterns: []string{"e2e-test"}})
	if err != nil {
		log.Fatalln(err)
	}
	buildRes, err := cli.ImageBuild(ctx, tar, types.ImageBuildOptions{Tags: []string{dockerImageName}, Remove: true})
	if err != nil {
		log.Fatalln(err)
	}
	scanner := bufio.NewScanner(buildRes.Body)
	for scanner.Scan() {
		message := dockerBuildMessage{}
		err = json.Unmarshal(scanner.Bytes(), &message)
		if err != nil || len(message.Stream) == 0 {
			continue
		}
		fmt.Println("[DOCKER BUILD] " + strings.TrimSuffix(message.Stream, "\n"))
	}
	_ = buildRes.Body.Close()

	log.Println("Generating keys...")
	err = os.Mkdir(testCertsDir, os.ModeDir)
	if err != nil {
		log.Fatalln(err)
	}

	var identities []string

	for i := 0; i < numNodes; i++ {
		privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
		if err != nil {
			log.Fatalln(err)
		}
		pubKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
		pubKeyHash := sha256.Sum256(pubKeyBytes)
		identityString := hex.EncodeToString(pubKeyHash[:])
		identities = append(identities, identityString)

		pemFile, err := os.Create(testCertsDir + "/" + identityString + ".pem")
		if err != nil {
			log.Fatalln(err)
		}

		pemPrivateBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}
		pemPublicBlock := &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubKeyBytes,
		}

		err = pem.Encode(pemFile, pemPublicBlock)
		if err != nil {
			log.Fatalln(err)
		}
		err = pem.Encode(pemFile, pemPrivateBlock)
		if err != nil {
			log.Fatalln(err)
		}

		err = pemFile.Close()
		if err != nil {
			log.Fatalln(err)
		}

	}

	log.Println("Generating config.ini with bootstrap node...")
	cfgFileIn, err := os.Open(testConfigPath)
	if err != nil {
		log.Fatalln(err)
	}
	cfgFileOut, err := os.Create(bootstrappedTestConfigPath)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = io.Copy(cfgFileOut, cfgFileIn)
	if err != nil {
		log.Fatalln(err)
	}
	_ = cfgFileIn.Close()
	_, err = cfgFileOut.WriteString(fmt.Sprintf("\nbootstrap_nodes = %v,gossip-%v:7001", identities[0], identities[0]))
	if err != nil {
		log.Fatalln(err)
	}
	_ = cfgFileOut.Close()

	log.Println("Creating docker network...")
	_, err = cli.NetworkCreate(ctx, dockerNetworkName, types.NetworkCreate{Driver: "bridge"})
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Starting containers...")
	firstContainer := true
	for _, identity := range identities {
		containerCfg := container.Config{
			Image:   dockerImageName,
			Volumes: map[string]struct{}{},
			ExposedPorts: nat.PortSet{
				"7001/tcp": {},
			},
		}
		hostCfg := container.HostConfig{
			Mounts: []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: fmt.Sprintf("%v%v%v", cwd, string(os.PathSeparator), bootstrappedTestConfigPath),
					Target: "/config.ini",
				},
				{
					Type:   mount.TypeBind,
					Source: fmt.Sprintf("%v%v%v", cwd, string(os.PathSeparator), testCertsDir),
					Target: "/keys",
				},
				{
					Type:   mount.TypeBind,
					Source: fmt.Sprintf("%v%v%v%v%v.pem", cwd, string(os.PathSeparator), testCertsDir, string(os.PathSeparator), identity),
					Target: "/nodekey.pem",
				},
			},
		}
		networkCfg := network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{dockerNetworkName: {}},
		}
		if firstContainer {
			firstContainer = false
			hostCfg.PortBindings = nat.PortMap{"7001/tcp": []nat.PortBinding{{HostIP: "0.0.0.0", HostPort: "7001"}}}
			hostCfg.Mounts[0].Source = fmt.Sprintf("%v%v%v", cwd, string(os.PathSeparator), testConfigPath)
		}

		createRes, err := cli.ContainerCreate(ctx, &containerCfg, &hostCfg, &networkCfg, nil, "gossip-"+identity)
		if err != nil {
			log.Fatalln(err)
		}

		err = cli.ContainerStart(ctx, createRes.ID, types.ContainerStartOptions{})
		if err != nil {
			log.Fatalln(err)
		}
	}

	log.Println("API of container gossip-" + identities[0] + " is available at localhost:7001")
	log.Println("Finished!")
}

func runStopCommand() {
	ctx := context.Background()

	log.Println("Starting docker client...")
	cli, err := dockerClient.NewClientWithOpts(dockerClient.FromEnv, dockerClient.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Deleting containers...")
	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{All: true})
	if err != nil {
		log.Fatalln(err)
	}

	for _, c := range containers {
		if c.Image == dockerImageName {
			err = cli.ContainerRemove(ctx, c.ID, types.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
			if err != nil {
				log.Fatalln(err)
			}
		}
	}

	log.Println("Removing docker network...")
	networks, err := cli.NetworkList(ctx, types.NetworkListOptions{})
	if err != nil {
		log.Fatalln(err)
	}
	for _, n := range networks {
		if n.Name == dockerNetworkName {
			err = cli.NetworkRemove(ctx, n.ID)
			if err != nil {
				log.Fatalln(err)
			}
		}
	}

	log.Println("Deleting generated files...")
	err = os.RemoveAll(testCertsDir)
	if err != nil {
		log.Fatalln(err)
	}
	err = os.Remove(bootstrappedTestConfigPath)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Finished!")
}
