package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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
	MaxConnections     int
	NewMachine         MachineFactory
	Metrics            *telemetry.Metrics
	TerminateAuth      *TerminationAuth
}

type TerminationAuth struct {
	ClientUsername   string
	ClientPassword   string
	UpstreamUsername string
	UpstreamPassword string
	UpstreamDatabase string
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
	if auth := config.TerminateAuth; auth != nil {
		if !config.RequireClientTLS {
			return nil, errors.New("gateway: authentication termination requires client TLS")
		}
		if auth.ClientUsername == "" || auth.ClientPassword == "" || auth.UpstreamUsername == "" || auth.UpstreamPassword == "" || auth.UpstreamDatabase == "" {
			return nil, errors.New("gateway: authentication termination credentials and upstream database are required")
		}
		if !printableASCII(auth.ClientUsername) || !printableASCII(auth.ClientPassword) || !printableASCII(auth.UpstreamUsername) || !printableASCII(auth.UpstreamPassword) {
			return nil, errors.New("gateway: SCRAM credentials must use printable ASCII")
		}
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
	if config.MaxConnections <= 0 {
		config.MaxConnections = 1024
	}
	if config.MaxConnections > 100_000 {
		return nil, errors.New("gateway: max connections exceeds 100000")
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
	capacity := make(chan struct{}, s.config.MaxConnections)
	defer connections.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("gateway: accept: %w", err)
		}
		select {
		case capacity <- struct{}{}:
		case <-ctx.Done():
			_ = connection.Close()
			return nil
		}
		connections.Add(1)
		if s.config.Metrics != nil {
			s.config.Metrics.ConnectionsTotal.Add(1)
			s.config.Metrics.ConnectionsActive.Add(1)
		}
		go func() {
			defer connections.Done()
			defer func() { <-capacity }()
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
	if _, cancel := startup.(*pgproto3.CancelRequest); cancel {
		upstream, err := s.upstreamConnection(ctx)
		if err != nil {
			return err
		}
		defer upstream.Close()
		if err := sendEncoded(upstream, startup); err != nil {
			return fmt.Errorf("gateway: forward cancel request: %w", err)
		}
		return nil
	}

	clientReceiver := pgproto3.NewBackend(client, io.Discard)
	clientReceiver.SetMaxBodyLen(s.config.MaxMessageBytes)
	clientSender := pgproto3.NewBackend(nil, client)
	_ = client.SetDeadline(time.Now().Add(s.config.HandshakeTimeout))
	if s.config.TerminateAuth != nil {
		startupMessage, ok := startup.(*pgproto3.StartupMessage)
		if !ok || startupMessage.Parameters["user"] != s.config.TerminateAuth.ClientUsername {
			return errors.New("gateway: client authentication failed")
		}
		if err := authenticateClientSCRAM(clientReceiver, clientSender, s.config.TerminateAuth); err != nil {
			return err
		}
		upstream, status, err := s.authenticatedUpstream(ctx)
		if err != nil {
			return err
		}
		defer upstream.Close()
		if err := sendStartupStatus(clientSender, status); err != nil {
			return err
		}
		_ = client.SetDeadline(time.Time{})
		upstreamReceiver := pgproto3.NewFrontend(upstream, io.Discard)
		upstreamReceiver.SetMaxBodyLen(s.config.MaxMessageBytes)
		upstreamSender := pgproto3.NewFrontend(nil, upstream)
		return relaySession(ctx, client, upstream, clientReceiver, clientSender, upstreamReceiver, upstreamSender, machine)
	}

	upstream, err := s.upstreamConnection(ctx)
	if err != nil {
		return err
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(s.config.HandshakeTimeout))
	if err := sendEncoded(upstream, startup); err != nil {
		return fmt.Errorf("gateway: forward startup: %w", err)
	}
	upstreamReceiver := pgproto3.NewFrontend(upstream, io.Discard)
	upstreamReceiver.SetMaxBodyLen(s.config.MaxMessageBytes)
	upstreamSender := pgproto3.NewFrontend(nil, upstream)
	if err := relayAuthentication(clientReceiver, clientSender, upstreamReceiver, upstreamSender); err != nil {
		return err
	}
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
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

type upstreamStatus struct {
	processID  uint32
	secretKey  []byte
	parameters map[string]string
	txStatus   byte
}

func (s *Server) authenticatedUpstream(ctx context.Context) (net.Conn, upstreamStatus, error) {
	auth := s.config.TerminateAuth
	host, portText, err := net.SplitHostPort(s.config.UpstreamAddress)
	if err != nil {
		return nil, upstreamStatus{}, fmt.Errorf("gateway: parse upstream address: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, upstreamStatus{}, fmt.Errorf("gateway: parse upstream port: %w", err)
	}
	connectionURL := &url.URL{Scheme: "postgres", User: url.UserPassword(auth.UpstreamUsername, auth.UpstreamPassword), Host: net.JoinHostPort(host, portText), Path: "/" + auth.UpstreamDatabase}
	query := connectionURL.Query()
	query.Set("sslmode", "disable")
	query.Set("require_auth", "scram-sha-256")
	connectionURL.RawQuery = query.Encode()
	config, err := pgconn.ParseConfig(connectionURL.String())
	if err != nil {
		return nil, upstreamStatus{}, fmt.Errorf("gateway: build terminated upstream configuration: %w", err)
	}
	config.Host = host
	config.Port = uint16(port)
	config.ConnectTimeout = s.config.DialTimeout
	config.TLSConfig = s.config.UpstreamTLS
	config.Fallbacks = nil
	connection, err := pgconn.ConnectConfig(ctx, config)
	if err != nil {
		return nil, upstreamStatus{}, fmt.Errorf("gateway: authenticate terminated upstream connection: %w", err)
	}
	hijacked, err := connection.Hijack()
	if err != nil {
		_ = connection.Close(ctx)
		return nil, upstreamStatus{}, fmt.Errorf("gateway: take ownership of upstream connection: %w", err)
	}
	return hijacked.Conn, upstreamStatus{
		processID: hijacked.PID, secretKey: append([]byte(nil), hijacked.SecretKey...),
		parameters: hijacked.ParameterStatuses, txStatus: hijacked.TxStatus,
	}, nil
}

func authenticateClientSCRAM(receiver *pgproto3.Backend, sender *pgproto3.Backend, auth *TerminationAuth) error {
	conversation, err := newSCRAMServer(auth.ClientUsername, auth.ClientPassword)
	if err != nil {
		return err
	}
	receiver.SetAuthType(pgproto3.AuthTypeSASL)
	sender.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
	if err := sender.Flush(); err != nil {
		return fmt.Errorf("gateway: send SCRAM challenge: %w", err)
	}
	initialMessage, err := receiver.Receive()
	if err != nil {
		return fmt.Errorf("gateway: receive SCRAM initial response: %w", err)
	}
	initial, ok := initialMessage.(*pgproto3.SASLInitialResponse)
	if !ok || initial.AuthMechanism != "SCRAM-SHA-256" {
		return errors.New("gateway: client did not select SCRAM-SHA-256")
	}
	serverFirst, err := conversation.begin(initial.Data)
	if err != nil {
		return err
	}
	receiver.SetAuthType(pgproto3.AuthTypeSASLContinue)
	sender.Send(&pgproto3.AuthenticationSASLContinue{Data: serverFirst})
	if err := sender.Flush(); err != nil {
		return fmt.Errorf("gateway: send SCRAM continuation: %w", err)
	}
	finalMessage, err := receiver.Receive()
	if err != nil {
		return fmt.Errorf("gateway: receive SCRAM proof: %w", err)
	}
	final, ok := finalMessage.(*pgproto3.SASLResponse)
	if !ok {
		return errors.New("gateway: client SCRAM proof has the wrong protocol type")
	}
	serverFinal, err := conversation.finish(final.Data)
	if err != nil {
		return err
	}
	sender.Send(&pgproto3.AuthenticationSASLFinal{Data: serverFinal})
	if err := sender.Flush(); err != nil {
		return fmt.Errorf("gateway: send SCRAM verifier: %w", err)
	}
	return nil
}

func sendStartupStatus(sender *pgproto3.Backend, status upstreamStatus) error {
	sender.Send(&pgproto3.AuthenticationOk{})
	keys := make([]string, 0, len(status.parameters))
	for key := range status.parameters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		sender.Send(&pgproto3.ParameterStatus{Name: key, Value: status.parameters[key]})
	}
	sender.Send(&pgproto3.BackendKeyData{ProcessID: status.processID, SecretKey: status.secretKey})
	sender.Send(&pgproto3.ReadyForQuery{TxStatus: status.txStatus})
	if err := sender.Flush(); err != nil {
		return fmt.Errorf("gateway: send terminated authentication status: %w", err)
	}
	return nil
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
