package licensing

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"stratium/config"

	"github.com/golang-jwt/jwt/v5"
)

const defaultRefreshInterval = 5 * time.Minute

// State captures the most recent license evaluation result.
type State struct {
	Claims   *Claims
	Token    string
	LoadedAt time.Time
	Valid    bool
	Err      error
}

// Manager loads and validates offline licenses.
type Manager struct {
	cfg             config.LicenseConfig
	publicKey       interface{}
	refreshInterval time.Duration
	parser          *jwt.Parser

	mu         sync.RWMutex
	lastLoaded time.Time
	state      State
}

// NewManager initializes a license manager and validates the current license.
func NewManager(cfg config.LicenseConfig) (*Manager, error) {
	manager := &Manager{
		cfg:             cfg,
		refreshInterval: defaultRefreshInterval,
		parser:          jwt.NewParser(jwt.WithValidMethods([]string{"RS256"})),
		state: State{
			Valid: !cfg.Enabled,
		},
	}

	if !cfg.Enabled {
		return manager, nil
	}

	if cfg.File == "" {
		return nil, fmt.Errorf("license.file is required when license is enabled")
	}
	if cfg.PublicKeyFile == "" {
		return nil, fmt.Errorf("license.public_key_file is required when license is enabled")
	}

	if cfg.RefreshInterval > 0 {
		manager.refreshInterval = cfg.RefreshInterval
	}

	publicKey, err := loadPublicKey(cfg.PublicKeyFile)
	if err != nil {
		return nil, err
	}
	manager.publicKey = publicKey

	if err := manager.refresh(); err != nil {
		return nil, err
	}

	return manager, nil
}

// Enabled returns true when license enforcement is configured.
func (m *Manager) Enabled() bool {
	if m == nil {
		return false
	}
	return m.cfg.Enabled
}

// State returns a snapshot of the most recent license evaluation.
func (m *Manager) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// ValidateService checks that the license permits access to the requested service.
func (m *Manager) ValidateService(serviceName string) error {
	if !m.Enabled() {
		return nil
	}

	state, err := m.refreshIfNeeded()
	if err != nil {
		return err
	}

	if !state.Valid {
		return normalizeError(state.Err, "license is invalid")
	}

	if state.Claims == nil {
		return errors.New("license claims missing")
	}

	if err := validateTimeClaims(state.Claims, time.Now()); err != nil {
		return err
	}

	if !state.Claims.MatchesDeployment(m.cfg.DeploymentID) {
		return fmt.Errorf("license deployment ID mismatch")
	}

	if !state.Claims.AllowsService(serviceName) {
		return fmt.Errorf("license does not allow service %s", serviceName)
	}

	return nil
}

func (m *Manager) refreshIfNeeded() (State, error) {
	m.mu.RLock()
	refreshInterval := m.refreshInterval
	lastLoaded := m.lastLoaded
	m.mu.RUnlock()

	if refreshInterval > 0 && time.Since(lastLoaded) < refreshInterval {
		return m.State(), nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if refreshInterval > 0 && time.Since(m.lastLoaded) < refreshInterval {
		return m.state, nil
	}

	if err := m.refreshLocked(); err != nil {
		return m.state, err
	}

	return m.state, nil
}

func (m *Manager) refresh() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refreshLocked()
}

func (m *Manager) refreshLocked() error {
	claims, token, err := m.loadLicense()
	m.lastLoaded = time.Now()
	if err != nil {
		m.state = State{
			Valid:    false,
			Err:      err,
			LoadedAt: m.lastLoaded,
		}
		return err
	}

	m.state = State{
		Claims:   claims,
		Token:    token,
		LoadedAt: m.lastLoaded,
		Valid:    true,
	}
	return nil
}

func (m *Manager) loadLicense() (*Claims, string, error) {
	tokenBytes, err := os.ReadFile(m.cfg.File)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read license file: %w", err)
	}

	tokenString := strings.TrimSpace(string(tokenBytes))
	if tokenString == "" {
		return nil, "", errors.New("license file is empty")
	}

	claims := &Claims{}
	parsed, err := m.parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return m.publicKey, nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse license token: %w", err)
	}
	if parsed == nil || !parsed.Valid {
		return nil, "", errors.New("license token signature invalid")
	}

	return claims, tokenString, nil
}

func loadPublicKey(path string) (interface{}, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read license public key: %w", err)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse license public key: %w", err)
	}

	return publicKey, nil
}

func validateTimeClaims(claims *Claims, now time.Time) error {
	if claims.ExpiresAt != nil && now.After(claims.ExpiresAt.Time) {
		return fmt.Errorf("license expired at %s", claims.ExpiresAt.Time.Format(time.RFC3339))
	}
	if claims.NotBefore != nil && now.Before(claims.NotBefore.Time) {
		return fmt.Errorf("license not valid until %s", claims.NotBefore.Time.Format(time.RFC3339))
	}
	return nil
}

func normalizeError(err error, fallback string) error {
	if err == nil {
		return errors.New(fallback)
	}
	return err
}
