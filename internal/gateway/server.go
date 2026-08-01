package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/vendora-bit/pg-kms-gateway/internal/pgsession"
	"github.com/vendora-bit/pg-kms-gateway/internal/telemetry"
)

type MachineFactory func() (*pgsession.Machine, error)

type Config struct {
	UpstreamAddress    string
	ClientTLS          *tls.Config
	RequireClientTLS   bool
	UpstreamTLS        *tls.Config
	RequireUpstreamTLS bool
	DialTimeout        time.Duration
	HandshakeTimeout   time.Duration
	MaxMessageBytes    int
	NewMachine         MachineFactory
	Metrics            *telemetry.Metrics
}

type Server struct {
	config Config
}

func New(config Config) (*Server, error) {
	if config.UpstreamAddress == "" || config.NewMachine == nil {
		return nil, errors.New("gateway: upstream address and machine factory are required")
	}
	if config.RequireClientTLS && config.ClientTLS == nil {
		return nil, errors.New("gateway: client TLS is required but not configured")
	}
	if config.RequireUpstreamTLS && config.UpstreamTLS == nil {
		return nil, errors.New("gateway: upstream TLS is required but not configured")
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = 10 * time.Second
	}
	if config.HandshakeTimeout <= 0 {
		config.HandshakeTimeout = 10 * time.Second
	}
	if config.MaxMessageBytes <= 0 {
		config.MaxMessageBytes = 64 << 20
	}
	return &Server{config: config}, nil
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("gateway: listener is required")
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	var connections sync.WaitGroup
	defer connections.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("gateway: accept: %w", err)
		}
		connections.Add(1)
		if s.config.Metrics != nil {
			s.config.Metrics.ConnectionsTotal.Add(1)
			s.config.Metrics.ConnectionsActive.Add(1)
		}
		go func() {
			defer connections.Done()
			if s.config.Metrics != nil {
				defer s.config.Metrics.ConnectionsActive.Add(-1)
			}
			if err := s.Handle(ctx, connection); err != nil && s.config.Metrics != nil {
				s.config.Metrics.SessionErrorsTotal.Add(1)
			}
		}()
	}
}

func (s *Server) Handle(ctx context.Context, client net.Conn) error {
	defer client.Close()
	machine, err := s.config.NewMachine()
	if err != nil {
		return fmt.Errorf("gateway: initialize session: %w", err)
	}
	client, startup, err := s.clientStartup(ctx, client)
	if err != nil {
		return err
	}
	upstream, err := s.upstreamConnection(ctx)
	if err != nil {
		return err
	}
	defer upstream.Close()
	if err := sendEncoded(upstream, startup); err != nil {
		return fmt.Errorf("gateway: forward startup: %w", err)
	}
	if _, cancel := startup.(*pgproto3.CancelRequest); cancel {
		return nil
	}

	clientReceiver := pgproto3.NewBackend(client, io.Discard)
	clientReceiver.SetMaxBodyLen(s.config.MaxMessageBytes)
	clientSender := pgproto3.NewBackend(nil, client)
	upstreamReceiver := pgproto3.NewFrontend(upstream, io.Discard)
	upstreamReceiver.SetMaxBodyLen(s.config.MaxMessageBytes)
	upstreamSender := pgproto3.NewFrontend(nil, upstream)
	if err := relayAuthentication(clientReceiver, clientSender, upstreamReceiver, upstreamSender); err != nil {
		return err
	}
	return relaySession(ctx, client, upstream, clientReceiver, clientSender, upstreamReceiver, upstreamSender, machine)
}

func (s *Server) clientStartup(ctx context.Context, connection net.Conn) (net.Conn, pgproto3.FrontendMessage, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	} else {
		_ = connection.SetDeadline(time.Now().Add(s.config.HandshakeTimeout))
	}
	protocol := pgproto3.NewBackend(connection, connection)
	message, err := protocol.ReceiveStartupMessage()
	if err != nil {
		return nil, nil, fmt.Errorf("gateway: receive client startup: %w", err)
	}
	if _, sslRequested := message.(*pgproto3.SSLRequest); sslRequested {
		if s.config.ClientTLS == nil {
			if _, err := connection.Write([]byte{'N'}); err != nil {
				return nil, nil, fmt.Errorf("gateway: reject client TLS: %w", err)
			}
		} else {
			if _, err := connection.Write([]byte{'S'}); err != nil {
				return nil, nil, fmt.Errorf("gateway: accept client TLS: %w", err)
			}
			tlsConnection := tls.Server(connection, s.config.ClientTLS.Clone())
			if err := tlsConnection.HandshakeContext(ctx); err != nil {
				return nil, nil, fmt.Errorf("gateway: client TLS handshake: %w", err)
			}
			connection = tlsConnection
		}
		protocol = pgproto3.NewBackend(connection, connection)
		message, err = protocol.ReceiveStartupMessage()
		if err != nil {
			return nil, nil, fmt.Errorf("gateway: receive client startup after TLS negotiation: %w", err)
		}
	}
	if s.config.RequireClientTLS {
		if _, ok := connection.(*tls.Conn); !ok {
			return nil, nil, errors.New("gateway: client attempted a plaintext connection")
		}
	}
	_ = connection.SetDeadline(time.Time{})
	return connection, message, nil
}

func (s *Server) upstreamConnection(ctx context.Context) (net.Conn, error) {
	dialer := net.Dialer{Timeout: s.config.DialTimeout, KeepAlive: 30 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", s.config.UpstreamAddress)
	if err != nil {
		return nil, fmt.Errorf("gateway: dial upstream: %w", err)
	}
	if s.config.UpstreamTLS == nil {
		return connection, nil
	}
	if err := sendEncoded(connection, &pgproto3.SSLRequest{}); err != nil {
		connection.Close()
		return nil, fmt.Errorf("gateway: request upstream TLS: %w", err)
	}
	response := []byte{0}
	if _, err := io.ReadFull(connection, response); err != nil {
		connection.Close()
		return nil, fmt.Errorf("gateway: read upstream TLS response: %w", err)
	}
	if response[0] != 'S' {
		connection.Close()
		if s.config.RequireUpstreamTLS {
			return nil, errors.New("gateway: upstream refused required TLS")
		}
		return nil, errors.New("gateway: upstream TLS was configured but refused")
	}
	tlsConnection := tls.Client(connection, s.config.UpstreamTLS.Clone())
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		connection.Close()
		return nil, fmt.Errorf("gateway: upstream TLS handshake: %w", err)
	}
	return tlsConnection, nil
}

func relayAuthentication(clientReceiver, clientSender *pgproto3.Backend, upstreamReceiver, upstreamSender *pgproto3.Frontend) error {
	for {
		message, err := upstreamReceiver.Receive()
		if err != nil {
			return fmt.Errorf("gateway: receive upstream authentication: %w", err)
		}
		if authType, responseRequired := authenticationType(message); authType != 0 {
			if err := clientReceiver.SetAuthType(authType); err != nil {
				return fmt.Errorf("gateway: configure authentication relay: %w", err)
			}
			clientSender.Send(message)
			if err := clientSender.Flush(); err != nil {
				return fmt.Errorf("gateway: send authentication challenge: %w", err)
			}
			if responseRequired {
				response, err := clientReceiver.Receive()
				if err != nil {
					return fmt.Errorf("gateway: receive authentication response: %w", err)
				}
				upstreamSender.Send(response)
				if err := upstreamSender.Flush(); err != nil {
					return fmt.Errorf("gateway: forward authentication response: %w", err)
				}
			}
			continue
		}
		clientSender.Send(message)
		if err := clientSender.Flush(); err != nil {
			return fmt.Errorf("gateway: forward authentication status: %w", err)
		}
		switch message.(type) {
		case *pgproto3.ReadyForQuery:
			return nil
		case *pgproto3.ErrorResponse:
			return errors.New("gateway: upstream rejected startup")
		}
	}
}

func authenticationType(message pgproto3.BackendMessage) (uint32, bool) {
	switch message.(type) {
	case *pgproto3.AuthenticationCleartextPassword:
		return pgproto3.AuthTypeCleartextPassword, true
	case *pgproto3.AuthenticationMD5Password:
		return pgproto3.AuthTypeMD5Password, true
	case *pgproto3.AuthenticationSASL:
		return pgproto3.AuthTypeSASL, true
	case *pgproto3.AuthenticationSASLContinue:
		return pgproto3.AuthTypeSASLContinue, true
	case *pgproto3.AuthenticationSASLFinal:
		return pgproto3.AuthTypeSASLFinal, false
	case *pgproto3.AuthenticationGSS:
		return pgproto3.AuthTypeGSS, true
	case *pgproto3.AuthenticationGSSContinue:
		return pgproto3.AuthTypeGSSCont, true
	default:
		return 0, false
	}
}

func relaySession(
	ctx context.Context,
	clientConn, upstreamConn net.Conn,
	clientReceiver, clientSender *pgproto3.Backend,
	upstreamReceiver, upstreamSender *pgproto3.Frontend,
	machine *pgsession.Machine,
) error {
	type relayError struct {
		direction string
		err       error
	}
	errorsChannel := make(chan relayError, 2)
	var state sync.Mutex
	go func() {
		for {
			message, err := clientReceiver.Receive()
			if err != nil {
				errorsChannel <- relayError{"client", err}
				return
			}
			state.Lock()
			transformed, err := machine.Frontend(message)
			state.Unlock()
			if err != nil {
				errorsChannel <- relayError{"client transform", err}
				return
			}
			upstreamSender.Send(transformed)
			if err := upstreamSender.Flush(); err != nil {
				errorsChannel <- relayError{"upstream write", err}
				return
			}
		}
	}()
	go func() {
		for {
			message, err := upstreamReceiver.Receive()
			if err != nil {
				errorsChannel <- relayError{"upstream", err}
				return
			}
			state.Lock()
			transformed, err := machine.Backend(message)
			state.Unlock()
			if err != nil {
				errorsChannel <- relayError{"backend transform", err}
				return
			}
			clientSender.Send(transformed)
			if err := clientSender.Flush(); err != nil {
				errorsChannel <- relayError{"client write", err}
				return
			}
		}
	}()
	select {
	case <-ctx.Done():
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		return ctx.Err()
	case result := <-errorsChannel:
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		if errors.Is(result.err, io.EOF) || errors.Is(result.err, net.ErrClosed) {
			return nil
		}
		return fmt.Errorf("gateway: %s relay: %w", result.direction, result.err)
	}
}

type encodable interface {
	Encode([]byte) ([]byte, error)
}

func sendEncoded(writer io.Writer, message encodable) error {
	data, err := message.Encode(nil)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}
