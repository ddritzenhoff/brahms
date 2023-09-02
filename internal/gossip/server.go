package gossip

import (
	"bytes"
	"crypto/sha256"
	"gossiphers/internal/api"
	"gossiphers/internal/challenge"
	"gossiphers/internal/config"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

type Server struct {
	listener net.PacketConn
	ownNode  *Node

	// Channels to send nodes to the gossip implementation upon receiving valid push or pull packets
	pushNodes chan Node
	pullNodes chan Node

	// List of nodes used in pull responses to other peers
	pullResponseNodes      []Node
	mutexPullResponseNodes sync.RWMutex

	// Communication state with other peers, map from string(peerID) to list of conditional states the peer currently meets
	peerState      map[string][]peerCondition
	mutexPeerState sync.RWMutex

	// Channels used internally to resolve ping calls with the corresponding pong
	pongChannels      map[string]chan struct{}
	mutexPongChannels sync.RWMutex

	// challenger implementation to generate and verify computational puzzles
	challenger            *challenge.Challenger
	challengeDifficulty   uint32
	challengeMaxSolveTime time.Duration

	// internal state of messages that are currently spread by this gossip module
	messagesToSpread []spreadableMessage
	mutexMessages    sync.RWMutex

	apiServer *api.Server
	crypto    *Crypto
}

// spreadableMessage is the internal representation for a gossip message that will be exchanged with other nodes
// when received the TTL is decreased by 1, once it reaches 1 it is no longer forwarded
// A TTL or 0 indicates unlimited hops.
// The LocalTTL tracks for how many more cycles this peer will try and exchange this message with other nodes.
// Messages with a LocalTTL smaller or equal to 0 will no longer be forwarded,
// once they reach -24 they will be evicted from the local cache which also prevents them from being received multiple times.
type spreadableMessage struct {
	LocalTTL       int
	TTL            uint8
	DataType       uint16
	Data           []byte
	DataHash       []byte
	SourceIdentity []byte
}

// A peerCondition is a flag representing a communication state with a remote peer
type peerCondition int

const (
	AllowPull peerCondition = iota
	AllowMessage
	AllowPushChallenge
	DenyPush
)

// StartServer starts the UDP listener at the configured address
func StartServer(cfg *config.GossipConfig, pushNodes chan Node, pullNodes chan Node, gCrypto *Crypto, apiServer *api.Server) (*Server, error) {
	listener, err := net.ListenPacket("udp", cfg.GossipAddress)
	if err != nil {
		return nil, err
	}

	challenger, err := challenge.NewChallenger(time.Second*15, 4)
	if err != nil {
		return nil, err
	}

	ownIdentity, err := generateIdentity(&cfg.PrivateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	ownNode, err := NewNode([]byte(*ownIdentity), cfg.GossipAddress)
	if err != nil {
		return nil, err
	}

	server := Server{
		listener:              listener,
		ownNode:               ownNode,
		pushNodes:             pushNodes,
		pullNodes:             pullNodes,
		peerState:             make(map[string][]peerCondition),
		pongChannels:          make(map[string]chan struct{}),
		challenger:            challenger,
		challengeDifficulty:   uint32(cfg.ChallengeDifficulty),
		challengeMaxSolveTime: time.Millisecond * time.Duration(cfg.ChallengeMaxSolveMs),
		apiServer:             apiServer,
		crypto:                gCrypto,
	}

	// Automatically spread messages given to us by API clients
	server.apiServer.RegisterGossipAnnounceHandler(func(ttl uint8, dataType uint16, data []byte) {
		server.spreadMessage(ttl, dataType, data)
	})

	zap.L().Info("Gossip Server listening", zap.String("address", cfg.GossipAddress))
	go server.listenForPackets()

	return &server, nil
}

// ResetPeerStates should be called between two gossip rounds, clearing the servers internal state for peers and decaying messages
func (s *Server) ResetPeerStates() {
	s.mutexPeerState.Lock()
	s.peerState = make(map[string][]peerCondition)
	s.mutexPeerState.Unlock()

	// decay local message TTL, delete messages with TTL=0
	s.mutexMessages.Lock()
	var newMessages []spreadableMessage
	for _, msg := range s.messagesToSpread {
		msg.LocalTTL--
		if msg.LocalTTL > -24 {
			newMessages = append(newMessages, msg)
		}
	}
	s.messagesToSpread = newMessages
	s.mutexMessages.Unlock()
}

// UpdatePullResponseNodes should be called by the gossip logic to update the nodes used in pull responses regularly
func (s *Server) UpdatePullResponseNodes(nodes []Node) {
	s.mutexPullResponseNodes.Lock()
	s.pullResponseNodes = nodes
	s.mutexPullResponseNodes.Unlock()
}

func (s *Server) listenForPackets() {
	defer s.listener.Close()
	for {
		buf := make([]byte, 65535)
		numBytes, fromAddr, err := s.listener.ReadFrom(buf)
		if err != nil {
			zap.L().Warn("Error reading gossip packet from UDP socket", zap.Error(err))
			continue
		}
		packetBytes := buf[:numBytes]

		go s.handleIncomingBytes(packetBytes, fromAddr)
	}
}

func (s *Server) handleIncomingBytes(packetBytes []byte, fromAddr net.Addr) {
	if len(packetBytes) < PacketHeaderSize+SignatureSize {
		zap.L().Info("Received gossip packet with invalid length")
		return
	}
	decryptedBytes, err := s.crypto.DecryptRSA(packetBytes)
	if err != nil {
		zap.L().Error("Could not decrypt received gossip packet", zap.Error(err))
		return
	}

	header, err := ParsePacketHeader(decryptedBytes[:PacketHeaderSize])
	if err != nil {
		zap.L().Info("Received gossip packet with invalid header", zap.Error(err))
		return
	}

	senderIdentity, err := NewIdentity(header.SenderIdentity)
	if err != nil {
		zap.L().Error("Could not create identity from received gossip packet", zap.Error(err))
		return
	}

	err = s.crypto.VerifySignature(packetBytes[:len(packetBytes)-SignatureSize], packetBytes[len(packetBytes)-SignatureSize:], *senderIdentity)
	if err != nil {
		zap.L().Info("Signature on received gossip packet could not be validated", zap.Error(err), zap.String("sender_address", fromAddr.String()))
		return
	}

	switch header.Type {
	case MessageTypeGossipPing:
		packet := PacketPing{}
		err = packet.Parse(header, bytes.NewReader(decryptedBytes[PacketHeaderSize:]))
		if err != nil {
			break
		}
		s.handlePing(fromAddr, packet)
	case MessageTypeGossipPong:
		packet := PacketPong{}
		err = packet.Parse(header, bytes.NewReader(decryptedBytes[PacketHeaderSize:]))
		if err != nil {
			break
		}
		s.handlePong(fromAddr, packet)
	case MessageTypeGossipPullRequest:
		packet := PacketPullRequest{}
		err = packet.Parse(header, bytes.NewReader(decryptedBytes[PacketHeaderSize:]))
		if err != nil {
			break
		}
		s.handlePullRequest(fromAddr, packet)
	case MessageTypeGossipPullResponse:
		packet := PacketPullResponse{}
		err = packet.Parse(header, bytes.NewReader(decryptedBytes[PacketHeaderSize:]))
		if err != nil {
			break
		}
		s.handlePullResponse(fromAddr, packet)
	case MessageTypeGossipPushRequest:
		packet := PacketPushRequest{}
		err = packet.Parse(header, bytes.NewReader(decryptedBytes[PacketHeaderSize:]))
		if err != nil {
			break
		}
		s.handlePushRequest(fromAddr, packet)
	case MessageTypeGossipPushChallenge:
		packet := PacketPushChallenge{}
		err = packet.Parse(header, bytes.NewReader(decryptedBytes[PacketHeaderSize:]))
		if err != nil {
			break
		}
		s.handlePushChallenge(fromAddr, packet)
	case MessageTypeGossipPush:
		packet := PacketPush{}
		err = packet.Parse(header, bytes.NewReader(decryptedBytes[PacketHeaderSize:]))
		if err != nil {
			break
		}
		s.handlePush(fromAddr, packet)
	case MessageTypeGossipMessage:
		packet := PacketMessage{}
		err = packet.Parse(header, bytes.NewReader(decryptedBytes[PacketHeaderSize:]))
		if err != nil {
			break
		}
		s.handleMessage(fromAddr, packet)
	}
	if err != nil {
		zap.L().Info("Received gossip packet with invalid content", zap.Error(err))
		return
	}
}

func (s *Server) sendBytes(packetBytes []byte, address string, receiverIdentity []byte) error {
	// Sign
	signature, err := s.crypto.Sign(packetBytes)
	if err != nil {
		zap.L().Warn("Error signing outgoing packet", zap.Error(err), zap.String("target_addr", address))
		return err
	}
	signedBytes := append(packetBytes, signature...)

	// RSA Encrypt
	encryptedBytes, err := s.crypto.EncryptRSA(signedBytes, Identity(receiverIdentity))
	if err != nil {
		zap.L().Warn("Error encrypting outgoing packet", zap.Error(err), zap.String("target_addr", address))
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}
	_, err = s.listener.WriteTo(encryptedBytes, addr)
	if err != nil {
		zap.L().Warn("Error writing outgoing packet", zap.Error(err), zap.String("target_addr", address))
		return err
	}
	return nil
}

func (s *Server) addPeerCondition(identity []byte, condition peerCondition) {
	s.mutexPeerState.Lock()
	defer s.mutexPeerState.Unlock()
	mapKey := string(identity)
	if allowedPackets, ok := s.peerState[mapKey]; ok {
		for _, ap := range allowedPackets {
			if ap == condition {
				return
			}
		}
		s.peerState[mapKey] = append(allowedPackets, condition)
	} else {
		s.peerState[mapKey] = []peerCondition{condition}
	}
}

func (s *Server) hasPeerCondition(identity []byte, condition peerCondition) bool {
	s.mutexPeerState.RLock()
	defer s.mutexPeerState.RUnlock()
	if allowedPackets, ok := s.peerState[string(identity)]; ok {
		for _, ap := range allowedPackets {
			if ap == condition {
				return true
			}
		}
	}
	return false
}

// sendGossipMessage sends a gossip message to a node.
// This should only be used with nodes that have previously responded with a pull response or accepted a push.
func (s *Server) sendGossipMessages(address string, receiverIdentity []byte) {
	s.mutexMessages.RLock()
	for _, msg := range s.messagesToSpread {
		if msg.LocalTTL <= 0 {
			continue
		}
		packet, err := NewPacketMessage(s.ownNode.Identity, msg.TTL, msg.DataType, msg.Data)
		if err != nil {
			zap.L().Error("Error creating MessagePacket", zap.Error(err))
			return
		}

		_ = s.sendBytes(packet.ToBytes(), address, receiverIdentity)
	}
	s.mutexMessages.RUnlock()
}

// Ping sends a ping packet to a given node and waits for a reply for the specified time.
// If a correct response is received within the timeout return true, otherwise return false.
func (s *Server) Ping(node *Node, timeout time.Duration) bool {
	pongChannel := make(chan struct{}, 1)

	s.mutexPongChannels.Lock()
	s.pongChannels[string(node.Identity)] = pongChannel
	s.mutexPongChannels.Unlock()

	defer func() {
		s.mutexPongChannels.Lock()
		delete(s.pongChannels, string(node.Identity))
		s.mutexPongChannels.Unlock()
	}()

	pingPacket, err := NewPacketPing(s.ownNode.Identity)
	if err != nil {
		zap.L().Error("Error creating PingPacket", zap.Error(err))
		return false
	}

	err = s.sendBytes(pingPacket.ToBytes(), node.Address, node.Identity)
	if err != nil {
		return false
	}

	select {
	case <-pongChannel:
		return true
	case <-time.After(timeout):
		return false
	}
}

// SendPullRequest sends a gossip pull request to a given node and consequently allows the node to respond to it
func (s *Server) SendPullRequest(node *Node) {
	packet, err := NewPacketPullRequest(s.ownNode.Identity)
	if err != nil {
		zap.L().Error("Error creating PullRequestPacket", zap.Error(err))
	}
	s.addPeerCondition(node.Identity, AllowPull)
	_ = s.sendBytes(packet.ToBytes(), node.Address, node.Identity)
}

// SendPushRequest sends a gossip push request to a node.
// The node can respond with a push challenge which is then solved and the node pushes its own identity and address
func (s *Server) SendPushRequest(node *Node) {
	packet, err := NewPacketPushRequest(s.ownNode.Identity)
	if err != nil {
		zap.L().Error("Error creating PushRequestPacket", zap.Error(err))
	}
	_ = s.sendBytes(packet.ToBytes(), node.Address, node.Identity)
}

// spreadMessage stores a given message into the servers internal message store, spreading it during push and pulls
// until the TTL has decayed to 1, a TTL of 0 indicates infinite hops.
func (s *Server) spreadMessage(ttl uint8, dataType uint16, data []byte) {
	hashFunc := sha256.New()
	hashFunc.Write(data)
	dataHash := hashFunc.Sum(nil)

	s.mutexMessages.Lock()
	defer s.mutexMessages.Unlock()

	s.messagesToSpread = append(s.messagesToSpread, spreadableMessage{
		LocalTTL:       int(ttl),
		TTL:            ttl,
		DataType:       dataType,
		Data:           data,
		DataHash:       dataHash,
		SourceIdentity: s.ownNode.Identity,
	})
}
