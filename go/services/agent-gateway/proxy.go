package agent_gateway

import (
	"context"
	"fmt"
	"sync"

	"stratium/config"
	"stratium/pkg/security/tlspolicy"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// ServiceProxy manages connections to downstream Stratium services
// and forwards authorized requests after double-hop evaluation.
type ServiceProxy struct {
	mu          sync.RWMutex
	connections map[string]*grpc.ClientConn
	cfg         *config.Config
}

// NewServiceProxy creates a proxy with lazy connections to downstream services.
func NewServiceProxy(cfg *config.Config) *ServiceProxy {
	return &ServiceProxy{
		connections: make(map[string]*grpc.ClientConn),
		cfg:         cfg,
	}
}

// Forward sends an authorized request to the target service and returns the response.
// The payload is a proto-encoded request message; the response is proto-encoded.
func (p *ServiceProxy) Forward(ctx context.Context, targetService, method string, payload []byte) ([]byte, error) {
	conn, err := p.getOrCreateConnection(targetService)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", targetService, err)
	}

	// Use the raw gRPC invoke to forward an arbitrary method
	var response rawMessage
	err = conn.Invoke(ctx, method, &rawMessage{data: payload}, &response)
	if err != nil {
		return nil, fmt.Errorf("forwarding to %s %s failed: %w", targetService, method, err)
	}

	return response.data, nil
}

// Close closes all downstream connections.
func (p *ServiceProxy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, conn := range p.connections {
		if err := conn.Close(); err != nil {
			logger.Warn("Failed to close connection to %s: %v", name, err)
		}
	}
	p.connections = make(map[string]*grpc.ClientConn)
}

func (p *ServiceProxy) getOrCreateConnection(service string) (*grpc.ClientConn, error) {
	p.mu.RLock()
	if conn, ok := p.connections[service]; ok {
		p.mu.RUnlock()
		return conn, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if conn, ok := p.connections[service]; ok {
		return conn, nil
	}

	endpoint, err := p.resolveEndpoint(service)
	if err != nil {
		return nil, err
	}

	creds, err := p.resolveCredentials(service)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(
		endpoint,
		grpc.WithTransportCredentials(creds),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create client for %s at %s: %w", service, endpoint, err)
	}

	p.connections[service] = conn
	logger.Info("Established proxy connection to %s at %s", service, endpoint)
	return conn, nil
}

func (p *ServiceProxy) resolveEndpoint(service string) (string, error) {
	switch service {
	case "platform":
		return p.cfg.Services.Platform.Address, nil
	case "key-manager":
		return p.cfg.Services.KeyManager.Address, nil
	case "key-access":
		return p.cfg.Services.KeyAccess.Address, nil
	default:
		return "", fmt.Errorf("unknown target service: %s", service)
	}
}

func (p *ServiceProxy) resolveCredentials(service string) (credentials.TransportCredentials, error) {
	var tlsCfg config.TLSConfig

	switch service {
	case "platform":
		tlsCfg = p.cfg.Services.Platform.TLS
	case "key-manager":
		tlsCfg = p.cfg.Services.KeyManager.TLS
	case "key-access":
		tlsCfg = p.cfg.Services.KeyAccess.TLS
	default:
		return insecure.NewCredentials(), nil
	}

	if !tlsCfg.Enabled {
		return insecure.NewCredentials(), nil
	}

	endpoint, _ := p.resolveEndpoint(service)
	tc, err := tlspolicy.LoadClientConfig(
		endpoint,
		tlsCfg.CAFile,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS for %s: %w", service, err)
	}
	return credentials.NewTLS(tc), nil
}

// rawMessage wraps raw bytes so they can be passed to grpc.Invoke
// without the gateway needing to know the concrete proto type.
type rawMessage struct {
	data []byte
}

func (m *rawMessage) ProtoMessage()  {}
func (m *rawMessage) Reset()         {}
func (m *rawMessage) String() string { return "" }
func (m *rawMessage) Marshal() ([]byte, error) {
	return m.data, nil
}
func (m *rawMessage) Unmarshal(b []byte) error {
	m.data = make([]byte, len(b))
	copy(m.data, b)
	return nil
}
