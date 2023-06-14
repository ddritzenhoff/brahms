package api

import (
	"bufio"
	"go.uber.org/zap"
	"gossiphers/internal/config"
	"net"
)

type Server struct {
	listener net.Listener
}

func StartServer(cfg *config.GossipConfig) (*Server, error) {
	listener, err := net.Listen("tcp", cfg.ApiAddress)
	if err != nil {
		return nil, err
	}

	defer listener.Close()

	zap.L().Info("API Server listening", zap.String("address", cfg.ApiAddress))

	server := Server{listener: listener}

	go server.listenForConnections()

	return &server, nil
}

func (s *Server) listenForConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			zap.L().Warn("Error accepting API connection", zap.Error(err))
			continue
		}

		go s.handleRequests(conn)
	}
}

func (s *Server) handleRequests(conn net.Conn) {
	zap.L().Info("New API Client connected", zap.String("client_address", conn.RemoteAddr().String()))
	defer zap.L().Info("API Client disconnected", zap.String("client_address", conn.RemoteAddr().String()))

	reader := bufio.NewReaderSize(conn, 32)

	for {
		headerBytes, err := reader.Peek(4)
		if err != nil {
			zap.L().Warn("Received invalid packet from API Client. Incomplete Header", zap.String("client_address", conn.RemoteAddr().String()))
			continue
		}
		header, err := ParsePacketHeader(headerBytes)
		if err != nil {
			zap.L().Warn("Received invalid packet from API Client. Invalid Header", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
			continue
		}

		// TODO: use packet
		switch header.Type {
		case MessageTypeGossipAnnounce:
			packet := GossipAnnounce{}
			err := packet.Parse(header, reader)
			if err != nil {
				zap.L().Warn("Could not parse GossipAnnounce packet.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
		case MessageTypeGossipNotify:
			packet := GossipNotify{}
			err := packet.Parse(header, reader)
			if err != nil {
				zap.L().Warn("Could not parse GossipNotify packet.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
		case MessageTypeGossipValidation:
			packet := GossipValidation{}
			err := packet.Parse(header, reader)
			if err != nil {
				zap.L().Warn("Could not parse GossipValidation packet.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
		}
	}
}
