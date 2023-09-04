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

// Server represents a udp listener with handlers for gossip-related messages.
type Server struct {
	cfg      *config.GossipConfig
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
	SourceIdentity Identity
}

// A peerCondition is a flag representing a communication state with a remote peer
type peerCondition int

const (
	AllowPull peerCondition = iota
	AllowMessage
	AllowPushChallenge
	DenyPush
)

// NewServer returns a new instance of Server.
func NewServer(cfg *config.GossipConfig, pushNodes chan Node, pullNodes chan Node, gCrypto *Crypto, apiServer *api.Server) (*Server, error) {
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
		cfg:                   cfg,
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

	return &server, nil
}

// Start starts the UDP listener at the configured address
func (s *Server) Start() error {
	listener, err := net.ListenPacket("udp", s.cfg.GossipAddress)
	if err != nil {
		return err
	}
	s.listener = listener

	zap.L().Info("Gossip Server listening", zap.String("address", s.cfg.GossipAddress))
	go s.listenForPackets()
	return nil
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

// listenForPackets accepts network packets and forwards them to handlers
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

// handleIncomingBytes determines the request type of the packet by means of the header and handles it accordingly.
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

	err = s.crypto.VerifySignature(packetBytes[:len(packetBytes)-SignatureSize], packetBytes[len(packetBytes)-SignatureSize:], header.SenderIdentity)
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

// sendBytes sends a packet to a select address.
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

// addPeerCondition adds a conditional state to a peer.
func (s *Server) addPeerCondition(identity Identity, condition peerCondition) {
	s.mutexPeerState.Lock()
	defer s.mutexPeerState.Unlock()
	mapKey := identity.String()
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

// hasPeerCondition checks to see if a peer currently has a conditional state associated with it.
func (s *Server) hasPeerCondition(identity Identity, condition peerCondition) bool {
	s.mutexPeerState.RLock()
	defer s.mutexPeerState.RUnlock()
	if allowedPackets, ok := s.peerState[identity.String()]; ok {
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
	s.pongChannels[node.Identity.String()] = pongChannel
	s.mutexPongChannels.Unlock()

	defer func() {
		s.mutexPongChannels.Lock()
		delete(s.pongChannels, node.Identity.String())
		s.mutexPongChannels.Unlock()
	}()

	pingPacket, err := NewPacketPing(s.ownNode.Identity)
	if err != nil {
		zap.L().Error("Error creating PingPacket", zap.Error(err))
		return false
	}

	err = s.sendBytes(pingPacket.ToBytes(), node.Address, node.Identity.ToBytes())
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
	_ = s.sendBytes(packet.ToBytes(), node.Address, node.Identity.ToBytes())
}

// SendPushRequest sends a gossip push request to a node.
// The node can respond with a push challenge which is then solved and the node pushes its own identity and address
func (s *Server) SendPushRequest(node *Node) {
	packet, err := NewPacketPushRequest(s.ownNode.Identity)
	if err != nil {
		zap.L().Error("Error creating PushRequestPacket", zap.Error(err))
	}
	_ = s.sendBytes(packet.ToBytes(), node.Address, node.Identity.ToBytes())
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
