package gossip

import (
	"bytes"
	"context"
	"crypto/sha256"
	"gossiphers/internal/api"
	"gossiphers/internal/challenge"
	"net"

	"go.uber.org/zap"
)

// handlePing handles the ping message type.
func (s *Server) handlePing(fromAddr net.Addr, packet PacketPing) {
	pingPacket, err := NewPacketPong(s.ownNode.Identity)
	if err != nil {
		zap.L().Error("Error creating PongPacket", zap.Error(err))
		return
	}
	_ = s.sendBytes(pingPacket.ToBytes(), fromAddr.String(), packet.SenderIdentity)
}

// handlePong handles the pong message type.
func (s *Server) handlePong(_ net.Addr, packet PacketPong) {
	s.mutexPongChannels.RLock()
	if ch, ok := s.pongChannels[string(packet.SenderIdentity)]; ok {
		ch <- struct{}{}
	}
	s.mutexPongChannels.RUnlock()
}

// handlePullRequest handles the pull request message type.
func (s *Server) handlePullRequest(fromAddr net.Addr, packet PacketPullRequest) {
	s.mutexPullResponseNodes.RLock()
	responsePacket, err := NewPacketPullResponse(s.ownNode.Identity, s.pullResponseNodes)
	if err != nil {
		zap.L().Warn("Error creating pull response packet", zap.Error(err))
		return
	}
	_ = s.sendBytes(responsePacket.ToBytes(), fromAddr.String(), packet.SenderIdentity)
	s.mutexPullResponseNodes.RUnlock()
	s.sendGossipMessages(fromAddr.String(), packet.SenderIdentity)
}

// handlePullResponse handles the pull response message type.
func (s *Server) handlePullResponse(_ net.Addr, packet PacketPullResponse) {
	if !s.hasPeerCondition(packet.SenderIdentity, AllowPull) {
		return
	}
	// Allow message exchange after pull response
	s.addPeerCondition(packet.SenderIdentity, AllowMessage)
	for _, node := range packet.Nodes {
		s.pullNodes <- node
	}
}

// handlePushRequest handles the push request message type.
func (s *Server) handlePushRequest(fromAddr net.Addr, packet PacketPushRequest) {
	newChallenge, err := s.challenger.NewChallenge(packet.SenderIdentity.ToBytes())
	if err != nil {
		zap.L().Warn("Error generating challenge", zap.Error(err))
		return
	}
	challengePacket, err := NewPacketPushChallenge(s.ownNode.Identity, s.challengeDifficulty, newChallenge)
	if err != nil {
		zap.L().Error("Error creating PushChallengePacket", zap.Error(err))
		return
	}
	_ = s.sendBytes(challengePacket.ToBytes(), fromAddr.String(), packet.SenderIdentity)
}

// handlePushChallenge handles the push challenge message type.
func (s *Server) handlePushChallenge(fromAddr net.Addr, packet PacketPushChallenge) {
	if !s.hasPeerCondition(packet.SenderIdentity, AllowPushChallenge) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.challengeMaxSolveTime)
	defer cancel()
	nonce, err := challenge.SolveChallenge(packet.Challenge, int(packet.Difficulty), ctx)
	if err != nil {
		zap.L().Warn("Error solving challenge", zap.Error(err))
		return
	}

	pushPacket, err := NewPacketPush(s.ownNode.Identity, packet.Challenge, nonce, *s.ownNode)
	if err != nil {
		zap.L().Error("Error creating PushPacket", zap.Error(err))
		return
	}

	_ = s.sendBytes(pushPacket.ToBytes(), fromAddr.String(), packet.SenderIdentity)
	s.sendGossipMessages(fromAddr.String(), packet.SenderIdentity)
}

// handlePush handles the push message type.
func (s *Server) handlePush(_ net.Addr, packet PacketPush) {
	// Allow only one push per node per cycle
	if s.hasPeerCondition(packet.SenderIdentity, DenyPush) {
		return
	}
	s.addPeerCondition(packet.SenderIdentity, DenyPush)

	challengeOk, err := s.challenger.IsSolvedCorrectly(packet.Challenge, packet.Nonce, packet.SenderIdentity.ToBytes(), int(s.challengeDifficulty))
	if err != nil {
		zap.L().Warn("Error during challenge verification", zap.Error(err))
	}
	if !challengeOk {
		return
	}
	if !bytes.Equal(packet.SenderIdentity.ToBytes(), packet.Node.Identity.ToBytes()) {
		zap.L().Warn("Node tried pushing reference to a third party node, rejected.", zap.String("sender_identity", string(packet.SenderIdentity)))
		return
	}
	// Allow message exchange after push response
	s.addPeerCondition(packet.SenderIdentity, AllowMessage)
	s.pushNodes <- packet.Node
}

// handleMessage handles the gossip-message message type.
func (s *Server) handleMessage(fromAddr net.Addr, packet PacketMessage) {
	if !s.hasPeerCondition(packet.SenderIdentity, AllowMessage) {
		return
	}
	hashFunc := sha256.New()
	hashFunc.Write(packet.Data)
	dataHash := hashFunc.Sum(nil)
	s.mutexMessages.Lock()
	messagesSameSource := 0
	for _, msg := range s.messagesToSpread {
		// ignore messages that are already known
		if msg.DataType == packet.DataType && bytes.Equal(msg.DataHash, dataHash) {
			return
		}
		if bytes.Equal(packet.SenderIdentity.ToBytes(), msg.SourceIdentity.ToBytes()) {
			messagesSameSource++
		}
	}

	// ignore message if we have too many concurrent messages from that peer in our storage
	if messagesSameSource > 50 {
		zap.L().Info("Ignored gossip message to prevent message flooding", zap.String("source_identity", string(packet.SenderIdentity)), zap.String("source_address", fromAddr.String()))
		return
	}
	var newTTL uint8 = 0
	localTTL := 255
	if packet.TTL != 0 {
		newTTL = packet.TTL - 1
		localTTL = int(newTTL)
	}
	s.messagesToSpread = append(s.messagesToSpread, spreadableMessage{
		LocalTTL:       localTTL,
		TTL:            newTTL,
		DataType:       packet.DataType,
		Data:           packet.Data,
		DataHash:       dataHash,
		SourceIdentity: packet.SenderIdentity,
	})
	s.mutexMessages.Unlock()

	// forward newly received message to API clients
	apiPacket, err := api.NewGossipNotification(packet.DataType, packet.Data)
	if err != nil {
		zap.L().Error("Error building API gossip notification packet", zap.Error(err))
		return
	}
	s.apiServer.SendGossipNotifications(*apiPacket, func(valid bool) {
		if valid {
			return
		}
		// Remove invalid packet from internal state to stop it from spreading further
		s.mutexMessages.Lock()
		var newMessages []spreadableMessage
		for _, msg := range s.messagesToSpread {
			if !bytes.Equal(msg.DataHash, dataHash) {
				newMessages = append(newMessages, msg)
			}
		}
		s.messagesToSpread = newMessages
		s.mutexMessages.Unlock()
	})
}
