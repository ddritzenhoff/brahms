package gossip

import (
	"bufio"
	"go.uber.org/zap"
	"gossiphers/internal/config"
	"net"
)

type Server struct {
	listener net.Listener
	gossip   *Gossip
}

func startServer(cfg *config.GossipConfig, gossip *Gossip) (*Server, error) {
	listener, err := net.Listen("tcp", cfg.P2PAddress)
	if err != nil {
		return nil, err
	}

	defer listener.Close()

	zap.L().Info("Gossip Server listening", zap.String("address", cfg.P2PAddress))

	server := Server{listener: listener, gossip: gossip}

	go server.listenForConnections()

	return &server, nil
}

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

func (s *Server) handleRequests(conn net.Conn) {
	zap.L().Debug("New P2P Client connected", zap.String("client_address", conn.RemoteAddr().String()))
	defer zap.L().Debug("P2P Client disconnected", zap.String("client_address", conn.RemoteAddr().String()))

	reader := bufio.NewReaderSize(conn, 32)

	for {
		headerBytes, err := reader.Peek(4)
		if err != nil {
			zap.L().Warn("Received invalid packet from Gossip Client. Incomplete Header", zap.String("client_address", conn.RemoteAddr().String()))
			continue
		}

		// TODO: Accept GOSSIP PULL REQUEST, GOSSIP PUSH REQUEST -> GOSSIP PUSH (after challenging), GOSSIP PING, GOSSIP MESSAGE
		// TODO: Write sanitized Pushes into List that can be pulled and emptied frequently by gossip --> Sanitized by source IP and Computation challenge
		println(headerBytes)
	}
}

// TODO: functions for outgoing TCP message flows
