package gossip

import (
	"bufio"
	"context"
	"fmt"
	"gossiphers/internal/challenge"
	"gossiphers/internal/config"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Server represents the P2P API server.
type Server struct {
	pulls      chan<- View
	pushes     chan<- Node
	listener   net.Listener
	gossip     *Gossip
	challenger challenge.Challenger
	cfg        *config.GossipConfig
}

// NewServer returns a new instance of Server.
func NewServer(pushes chan<- Node, pulls chan<- View, gossip *Gossip, challenger challenge.Challenger) Server {
	return Server{
		pushes:     pushes,
		pulls:      pulls,
		gossip:     gossip,
		challenger: challenger,
		cfg:        gossip.cfg,
	}
}

// Open begins listening on the bind address.
func (s *Server) Open() error {
	listener, err := net.Listen("tcp", s.cfg.P2PAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	s.listener = listener
	zap.L().Info("Gossip Server listening", zap.String("address", s.cfg.P2PAddress))

	go s.listenForConnections()
	return nil
}

// listenForConnections listenes for incoming connections and dispatches a handler for each.
func (s *Server) listenForConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			zap.L().Warn("Error accepting P2P connection", zap.Error(err))
			continue
		}

		go s.handleRequests(conn)
	}
}

// handleRequests parses each request and calls the respective handler depending on the packet type.
func (s *Server) handleRequests(conn net.Conn) {
	zap.L().Debug("New P2P Client connected", zap.String("client_address", conn.RemoteAddr().String()))
	defer zap.L().Debug("P2P Client disconnected", zap.String("client_address", conn.RemoteAddr().String()))

	reader := bufio.NewReader(conn)

	for {
		headerBytes, err := reader.Peek(4)
		if err != nil {
			zap.L().Warn("Received invalid packet from Gossip Client. Incomplete Header", zap.String("client_address", conn.RemoteAddr().String()))
			continue
		}

		header, err := ParsePacketHeader(headerBytes)
		if err != nil {
			zap.L().Warn("Received invalid packet from API Client. Invalid Header", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
			continue
		}

		switch header.Type {
		case MessageTypeGossipPing:
			// TODO (ddritzenhoff) should I make this is another go routine?
			err = s.handlePing(conn)
			if err != nil {
				zap.L().Warn("Failed handling ping.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
		case MessageTypeGossipPong:
			err = s.handlePong(conn)
			if err != nil {
				zap.L().Warn("Failed handling pong.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
		case MessageTypeGossipPullRequest:
			err = s.handlePullRequest(conn)
			if err != nil {
				zap.L().Warn("Failed handling pull request.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
		case MessageTypeGossipPullResponse:
			p := PacketPullResponse{}
			err := p.Parse(header, reader)
			if err != nil {
				zap.L().Warn("Could not parse PullResponse packet.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
			err = s.handlePullResponse(conn, p)
			if err != nil {
				zap.L().Warn("Failed handling pull response.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
		case MessageTypeGossipPushRequest:
			err = s.handlePushRequest(conn)
			if err != nil {
				zap.L().Warn("Failed handling push request.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
		case MessageTypeGossipPushChallenge:
			p := PacketPushChallenge{}
			err := p.Parse(header, reader)
			if err != nil {
				zap.L().Warn("Could not parse PushChallenge packet.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
			err = s.handlePushChallenge(conn, p)
			if err != nil {
				zap.L().Warn("Failed handling push challange.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
		case MessageTypeGossipPush:
			p := PacketPush{}
			err := p.Parse(header, reader)
			if err != nil {
				zap.L().Warn("Could not parse Push packet.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
			err = s.handlePush(conn, p)
			if err != nil {
				zap.L().Warn("Failed handling Push packet.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
		case MessageTypeGossipMessage:
			p := PacketMessage{}
			err := p.Parse(header, reader)
			if err != nil {
				zap.L().Warn("Could not parse Message packet.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
			err = s.handleMessage(conn, p)
			if err != nil {
				zap.L().Warn("Failed handling Message packet.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
		}

		// TODO: Write sanitized Pushes into List that can be pulled and emptied frequently by gossip --> Sanitized by source IP and Computation challenge
	}
}

// handlePing handles the ping packet.
func (s *Server) handlePing(conn net.Conn) error {
	// Send pong response back to connection
	err := conn.SetWriteDeadline(time.Now().Add(time.Duration(s.cfg.ConnWriteTimeout) * time.Second))
	if err != nil {
		return err
	}
	resp := PacketPong{
		Size: PacketHeaderSize,
		Type: MessageTypeGossipPong,
	}
	_, err = conn.Write(resp.ToBytes())
	if err != nil {
		return err
	}
	return nil
}

// handlePong handles the pong packet.
func (s *Server) handlePong(conn net.Conn) error {
	return nil
}

// handlePullRequest handles the PullRequest packet.
func (s *Server) handlePullRequest(conn net.Conn) error {
	// Create comma delimited string of nodes. The last comma is left out.
	ns := make([]string, len(s.gossip.view.Nodes))
	for _, n := range s.gossip.view.Nodes {
		ns = append(ns, n.Identity())
	}
	commaDelimNodes := strings.Join(ns, ",")

	resp := PacketPullResponse{
		PacketHeader: PacketHeader{
			Size: PacketHeaderSize + uint16(len(commaDelimNodes)),
			Type: MessageTypeGossipPullResponse,
		},
		Nodes: []byte(commaDelimNodes),
	}

	// Send pull response back to connection.
	err := conn.SetWriteDeadline(time.Now().Add(s.cfg.ConnWriteTimeout))
	if err != nil {
		return err
	}
	_, err = conn.Write(resp.ToBytes())
	if err != nil {
		return err
	}
	return nil
}

// TODO (ddritzenhoff) technically, any peer can send a PullResponse packet without
// having first been issued a PullRequest. Does it make sense to add some sort of
// temporary key to validate the PullResponse packet?

// handlePullResponse handles the PullResponse packet.
func (s *Server) handlePullResponse(conn net.Conn, p PacketPullResponse) error {
	// Add nodes to pull list
	addrs := strings.Split(string(p.Nodes), ",")
	nodes := make([]Node, len(addrs))
	for _, addr := range addrs {
		nodes = append(nodes, Node{
			Address: addr,
		})
	}

	// Send the peer's view to the node's pull list.
	v := NewView(len(nodes), WithBootstrapNodes(nodes))
	s.pulls <- v
	return nil
}

// handlePushRequest handles the PushRequest packet.
func (s *Server) handlePushRequest(conn net.Conn) error {
	// Generate a challenge
	// TODO (ddritzenhoff) double check that you aren't sending the wrong address.
	chal, err := s.challenger.NewChallenge(conn.RemoteAddr().String())
	if err != nil {
		return err
	}

	resp := PacketPushChallenge{
		PacketHeader: PacketHeader{
			// PacketHeaderSize + 4 (difficulty --> uint32) + len(chal)
			Size: PacketHeaderSize + 4 + uint16(len(chal)),
			Type: MessageTypeGossipPushChallenge,
		},
		Difficulty: uint32(s.cfg.Difficulty),
		Challenge:  chal,
	}

	// Send a PacketPushChallenge back to the sender
	err = conn.SetWriteDeadline(time.Now().Add(s.cfg.ConnWriteTimeout))
	if err != nil {
		return err
	}

	_, err = conn.Write(resp.ToBytes())
	if err != nil {
		return err
	}
	return nil
}

// handlePushChallenge handles the PushChallenge packet.
func (s *Server) handlePushChallenge(conn net.Conn, p PacketPushChallenge) error {
	nonce, err := challenge.SolveChallenge(p.Challenge, s.cfg.Difficulty, context.TODO())
	if err != nil {
		return err
	}
	node := s.gossip.self.Identity()
	resp := PacketPush{
		PacketHeader: PacketHeader{
			Size: PacketHeaderSize + uint16(len(p.Challenge)) + uint16(len(nonce)) + uint16(len(node)),
			Type: MessageTypeGossipPush,
		},
		Challenge: p.Challenge,
		Nonce:     nonce,
		Node:      node,
	}

	// Send a PacketPush back to the sender
	err = conn.SetWriteDeadline(time.Now().Add(s.cfg.ConnWriteTimeout))
	if err != nil {
		return err
	}
	_, err = conn.Write(resp.ToBytes())
	if err != nil {
		return err
	}
	return nil
}

// handlePush handles the Push packet.
func (s *Server) handlePush(conn net.Conn, p PacketPush) error {
	// TODO (ddritzenhoff) What do we do if the challenge response is wrong?
	solved, err := s.challenger.IsSolvedCorrectly(p.Challenge, p.Nonce, conn.RemoteAddr().String(), int(s.cfg.Difficulty))
	if err != nil {
		return nil
	}

	if !solved {
		return fmt.Errorf("challenge not solved")
	}

	n := Node{
		Address: p.Node,
	}
	s.pushes <- n
	return nil
}

// handleMessage forwards the message packet to all of the node's peers.
func (s *Server) handleMessage(conn net.Conn, p PacketMessage) error {
	// TODO (ddritzenhoff) finish implementation.
	return nil
}
