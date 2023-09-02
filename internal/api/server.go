package api

import (
	"bufio"
	"bytes"
	"errors"
	"gossiphers/internal/config"
	"io"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Server represents a tcp listener.
type Server struct {
	listener                  net.Listener
	dataTypeToRegisteredConns map[uint16][]net.Conn
	gossipAnnounceHandlers    []GossipAnnounceHandler
	gossipValidationHandlers  []GossipValidationHandler
	gossipNotificationLock    sync.Mutex
}

// StartServer starts listening for tcp connections.
func StartServer(cfg *config.GossipConfig) (*Server, error) {
	listener, err := net.Listen("tcp", cfg.ApiAddress)
	if err != nil {
		return nil, err
	}

	zap.L().Info("API Server listening", zap.String("address", cfg.ApiAddress))

	server := Server{listener: listener, dataTypeToRegisteredConns: make(map[uint16][]net.Conn)}

	go server.listenForConnections()

	return &server, nil
}

// listenForConnections accepts network connection requests and forwards them to handlers.
func (s *Server) listenForConnections() {
	defer s.listener.Close()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			zap.L().Warn("Error accepting API connection", zap.Error(err))
			continue
		}

		go s.handleRequests(conn)
	}
}

// handleRequests determines the request type of the connection by means of the header and handles the packet accordingly.
func (s *Server) handleRequests(conn net.Conn) {
	zap.L().Info("New API Client connected", zap.String("client_address", conn.RemoteAddr().String()))
	defer func() {
		// deregister connection from data type mappings
		for dt, clients := range s.dataTypeToRegisteredConns {
			var newClients []net.Conn
			for _, c := range clients {
				if c != conn {
					newClients = append(newClients, c)
				}
			}
			s.dataTypeToRegisteredConns[dt] = newClients
		}
		_ = conn.Close()
		zap.L().Info("API Client disconnected", zap.String("client_address", conn.RemoteAddr().String()))
	}()

	buf := make([]byte, 65535)

	for {
		buf = make([]byte, 65535)
		numBytes, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			zap.L().Warn("Error reading packet from API connection", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
			break
		}

		reader := bufio.NewReader(bytes.NewReader(buf[:numBytes]))

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

		switch header.Type {
		case MessageTypeGossipAnnounce:
			packet := GossipAnnounce{}
			err := packet.Parse(header, reader)
			if err != nil {
				zap.L().Warn("Could not parse GossipAnnounce packet.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
			for _, handler := range s.gossipAnnounceHandlers {
				go handler(packet.TTL, packet.DataType, packet.Data)
			}
		case MessageTypeGossipNotify:
			packet := GossipNotify{}
			err := packet.Parse(header, reader)
			if err != nil {
				zap.L().Warn("Could not parse GossipNotify packet.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}
			// Register connection to receive notifications for given data type
			if clients, ok := s.dataTypeToRegisteredConns[packet.DataType]; ok {
				s.dataTypeToRegisteredConns[packet.DataType] = append(clients, conn)
			} else {
				s.dataTypeToRegisteredConns[packet.DataType] = []net.Conn{conn}
			}
		case MessageTypeGossipValidation:
			packet := GossipValidation{}
			err := packet.Parse(header, reader)
			if err != nil {
				zap.L().Warn("Could not parse GossipValidation packet.", zap.String("client_address", conn.RemoteAddr().String()), zap.Error(err))
				continue
			}

			for _, handler := range s.gossipValidationHandlers {
				if handler.messageID == packet.MessageID {
					handler.callback(packet.IsValid)
				}
			}
		}
	}
}

// GossipAnnounceHandler represents a handler for the Gossip Announce message.
type GossipAnnounceHandler func(ttl uint8, dataType uint16, data []byte)

// RegisterGossipAnnounceHandler registers a GossipAnnounceHandler.
func (s *Server) RegisterGossipAnnounceHandler(fn GossipAnnounceHandler) {
	s.gossipAnnounceHandlers = append(s.gossipAnnounceHandlers, fn)
}

// GossipValidationHandler represents a handler for the Gossip Validation message.
type GossipValidationHandler struct {
	callback    func(valid bool)
	messageID   uint16
	timeCreated time.Time
}

// SendGossipNotifications sends notification messages to all subscribed connections for that particular data type.
func (s *Server) SendGossipNotifications(notification GossipNotification, validationCallback func(valid bool)) {
	connections, ok := s.dataTypeToRegisteredConns[notification.DataType]
	if !ok {
		// No connections have registered this data type
		zap.L().Info("Could not distribute GossipNotifications, no API client registered for this data type.", zap.Uint16("data_type", notification.DataType))
		return
	}

	validationHandler := GossipValidationHandler{
		callback:    validationCallback,
		messageID:   notification.MessageID,
		timeCreated: time.Now(),
	}
	s.gossipValidationHandlers = append(s.gossipValidationHandlers, validationHandler)

	//Remove old validation handlers
	for len(s.gossipValidationHandlers) > 1 {
		if s.gossipValidationHandlers[0].timeCreated.Before(time.Now().Add(-10 * time.Second)) {
			s.gossipValidationHandlers = s.gossipValidationHandlers[1:]
		} else {
			break
		}
	}

	packetBytes := notification.ToBytes()

	// Send messages, prevent multiple goroutines accessing connection writers at the same time
	s.gossipNotificationLock.Lock()
	for _, conn := range connections {
		_, err := conn.Write(packetBytes)
		if err != nil {
			zap.L().Warn("Could not send gossip notification to API client", zap.Error(err), zap.String("client_address", conn.RemoteAddr().String()))
		}
	}
	s.gossipNotificationLock.Unlock()
}
