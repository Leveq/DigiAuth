package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/kdogg/digiauth/internal/config"
	"github.com/kdogg/digiauth/internal/domain"
)

// --- Mock Implementations ---

// MockUserRepository implements ports.UserRepository for testing.
type MockUserRepository struct {
	users       map[uuid.UUID]*domain.User
	byAddress   map[string]*domain.User
	CreateFunc  func(ctx context.Context, user *domain.User) (*domain.User, error)
	GetByIDFunc func(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users:     make(map[uuid.UUID]*domain.User),
		byAddress: make(map[string]*domain.User),
	}
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, user)
	}
	m.users[user.ID] = user
	m.byAddress[user.DGBAddress] = user
	return user, nil
}

func (m *MockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	if m.GetByIDFunc != nil {
		return m.GetByIDFunc(ctx, id)
	}
	if user, ok := m.users[id]; ok {
		return user, nil
	}
	return nil, errors.New("user not found")
}

func (m *MockUserRepository) GetByDGBAddress(ctx context.Context, address string) (*domain.User, error) {
	if user, ok := m.byAddress[address]; ok {
		return user, nil
	}
	return nil, errors.New("user not found")
}

func (m *MockUserRepository) Update(ctx context.Context, user *domain.User) (*domain.User, error) {
	m.users[user.ID] = user
	m.byAddress[user.DGBAddress] = user
	return user, nil
}

func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID, loginTime time.Time) error {
	if user, ok := m.users[id]; ok {
		user.LastLoginAt = &loginTime
		return nil
	}
	return errors.New("user not found")
}

// MockSessionRepository implements ports.SessionRepository for testing.
type MockSessionRepository struct {
	sessions   map[uuid.UUID]*domain.Session
	CreateFunc func(ctx context.Context, session *domain.Session) (*domain.Session, error)
}

func NewMockSessionRepository() *MockSessionRepository {
	return &MockSessionRepository{
		sessions: make(map[uuid.UUID]*domain.Session),
	}
}

func (m *MockSessionRepository) Create(ctx context.Context, session *domain.Session) (*domain.Session, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, session)
	}
	m.sessions[session.ID] = session
	return session, nil
}

func (m *MockSessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error) {
	if session, ok := m.sessions[id]; ok {
		return session, nil
	}
	return nil, errors.New("session not found")
}

func (m *MockSessionRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	var result []*domain.Session
	for _, s := range m.sessions {
		if s.UserID == userID {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *MockSessionRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	if session, ok := m.sessions[id]; ok {
		now := time.Now()
		session.RevokedAt = &now
		return nil
	}
	return errors.New("session not found")
}

func (m *MockSessionRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	for _, s := range m.sessions {
		if s.UserID == userID {
			s.RevokedAt = &now
		}
	}
	return nil
}

func (m *MockSessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	var count int64
	now := time.Now()
	for id, s := range m.sessions {
		if s.ExpiresAt.Before(now) {
			delete(m.sessions, id)
			count++
		}
	}
	return count, nil
}

// MockChallengeStore implements ports.ChallengeStore for testing.
type MockChallengeStore struct {
	challenges  map[string]*domain.Challenge
	results     map[string]*domain.ChallengeResult
	CreateFunc  func(ctx context.Context, challenge *domain.Challenge, ttl time.Duration) error
	GetFunc     func(ctx context.Context, nonce string) (*domain.Challenge, error)
	DeleteFunc  func(ctx context.Context, nonce string) error
	ResultError error
}

func NewMockChallengeStore() *MockChallengeStore {
	return &MockChallengeStore{
		challenges: make(map[string]*domain.Challenge),
		results:    make(map[string]*domain.ChallengeResult),
	}
}

func (m *MockChallengeStore) Create(ctx context.Context, challenge *domain.Challenge, ttl time.Duration) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, challenge, ttl)
	}
	m.challenges[challenge.Nonce] = challenge
	return nil
}

func (m *MockChallengeStore) Get(ctx context.Context, nonce string) (*domain.Challenge, error) {
	if m.GetFunc != nil {
		return m.GetFunc(ctx, nonce)
	}
	if challenge, ok := m.challenges[nonce]; ok {
		return challenge, nil
	}
	return nil, nil
}

func (m *MockChallengeStore) Delete(ctx context.Context, nonce string) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, nonce)
	}
	delete(m.challenges, nonce)
	return nil
}

func (m *MockChallengeStore) SetResult(ctx context.Context, nonce string, result *domain.ChallengeResult, ttl time.Duration) error {
	if m.ResultError != nil {
		return m.ResultError
	}
	m.results[nonce] = result
	return nil
}

func (m *MockChallengeStore) GetResult(ctx context.Context, nonce string) (*domain.ChallengeResult, error) {
	if result, ok := m.results[nonce]; ok {
		return result, nil
	}
	return nil, nil
}

// --- Test Helpers ---

func generateTestRSAKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

func newTestConfig() *config.Config {
	return &config.Config{
		Auth: config.AuthConfig{
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 30 * 24 * time.Hour,
		},
		DigiID: config.DigiIDConfig{
			CallbackURL:  "http://localhost:8080/api/v1/auth/callback",
			ChallengeTTL: 5 * time.Minute,
			Unsecure:     true,
		},
	}
}

func newTestAuthService(t *testing.T) (*AuthService, *MockUserRepository, *MockSessionRepository, *MockChallengeStore) {
	t.Helper()

	userRepo := NewMockUserRepository()
	sessionRepo := NewMockSessionRepository()
	challengeStore := NewMockChallengeStore()
	cfg := newTestConfig()
	privateKey, publicKey := generateTestRSAKeys(t)

	svc := NewAuthService(userRepo, sessionRepo, challengeStore, cfg, privateKey, publicKey)
	return svc, userRepo, sessionRepo, challengeStore
}

// --- Tests ---

func TestNewAuthService(t *testing.T) {
	svc, _, _, _ := newTestAuthService(t)
	if svc == nil {
		t.Fatal("NewAuthService returned nil")
	}
}

func TestAuthService_CreateChallenge(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, _, _, challengeStore := newTestAuthService(t)
		ctx := context.Background()

		resp, err := svc.CreateChallenge(ctx)
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}

		// Verify response
		if resp.Nonce == "" {
			t.Error("CreateChallenge() nonce is empty")
		}
		if len(resp.Nonce) != 64 { // 32 bytes hex encoded
			t.Errorf("CreateChallenge() nonce length = %d, want 64", len(resp.Nonce))
		}
		if resp.URI == "" {
			t.Error("CreateChallenge() URI is empty")
		}
		if resp.ExpiresIn != 300 { // 5 minutes
			t.Errorf("CreateChallenge() ExpiresIn = %d, want 300", resp.ExpiresIn)
		}

		// Verify challenge was stored
		if _, ok := challengeStore.challenges[resp.Nonce]; !ok {
			t.Error("CreateChallenge() challenge was not stored")
		}
	})

	t.Run("store failure", func(t *testing.T) {
		svc, _, _, challengeStore := newTestAuthService(t)
		challengeStore.CreateFunc = func(ctx context.Context, challenge *domain.Challenge, ttl time.Duration) error {
			return errors.New("redis connection failed")
		}

		ctx := context.Background()
		_, err := svc.CreateChallenge(ctx)
		if err == nil {
			t.Error("CreateChallenge() expected error when store fails")
		}
	})
}

func TestAuthService_PollResult(t *testing.T) {
	t.Run("result exists", func(t *testing.T) {
		svc, _, _, challengeStore := newTestAuthService(t)
		ctx := context.Background()

		nonce := "test-nonce-123"
		expected := &domain.ChallengeResult{
			Nonce:        nonce,
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    900,
			UserID:       uuid.New().String(),
		}
		challengeStore.results[nonce] = expected

		result, err := svc.PollResult(ctx, nonce)
		if err != nil {
			t.Fatalf("PollResult() error = %v", err)
		}
		if result == nil {
			t.Fatal("PollResult() returned nil")
		}
		if result.Nonce != expected.Nonce {
			t.Errorf("PollResult() nonce = %v, want %v", result.Nonce, expected.Nonce)
		}
		if result.AccessToken != expected.AccessToken {
			t.Errorf("PollResult() access token mismatch")
		}
	})

	t.Run("result not found", func(t *testing.T) {
		svc, _, _, _ := newTestAuthService(t)
		ctx := context.Background()

		result, err := svc.PollResult(ctx, "nonexistent-nonce")
		if err != nil {
			t.Fatalf("PollResult() error = %v (expected nil)", err)
		}
		if result != nil {
			t.Error("PollResult() expected nil for nonexistent nonce")
		}
	})
}

func TestAuthService_ValidateAccessToken(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		svc, _, _, _ := newTestAuthService(t)

		// Generate a valid token
		userID := uuid.New()
		dgbAddress := "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs"
		now := time.Now()

		claims := jwt.MapClaims{
			"sub":         userID.String(),
			"dgb_address": dgbAddress,
			"iat":         now.Unix(),
			"exp":         now.Add(15 * time.Minute).Unix(),
			"iss":         "digiauth",
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, err := token.SignedString(svc.privateKey)
		if err != nil {
			t.Fatalf("failed to create test token: %v", err)
		}

		// Validate
		result, err := svc.ValidateAccessToken(tokenString)
		if err != nil {
			t.Fatalf("ValidateAccessToken() error = %v", err)
		}
		if result.UserID != userID {
			t.Errorf("ValidateAccessToken() userID = %v, want %v", result.UserID, userID)
		}
		if result.DGBAddress != dgbAddress {
			t.Errorf("ValidateAccessToken() dgbAddress = %v, want %v", result.DGBAddress, dgbAddress)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		svc, _, _, _ := newTestAuthService(t)

		userID := uuid.New()
		past := time.Now().Add(-1 * time.Hour)

		claims := jwt.MapClaims{
			"sub":         userID.String(),
			"dgb_address": "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
			"iat":         past.Unix(),
			"exp":         past.Add(15 * time.Minute).Unix(), // Expired
			"iss":         "digiauth",
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, _ := token.SignedString(svc.privateKey)

		_, err := svc.ValidateAccessToken(tokenString)
		if err == nil {
			t.Error("ValidateAccessToken() expected error for expired token")
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		svc, _, _, _ := newTestAuthService(t)

		// Create token with different key
		otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		claims := jwt.MapClaims{
			"sub":         uuid.New().String(),
			"dgb_address": "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
			"iat":         time.Now().Unix(),
			"exp":         time.Now().Add(15 * time.Minute).Unix(),
			"iss":         "digiauth",
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, _ := token.SignedString(otherKey)

		_, err := svc.ValidateAccessToken(tokenString)
		if err == nil {
			t.Error("ValidateAccessToken() expected error for invalid signature")
		}
	})

	t.Run("wrong signing method", func(t *testing.T) {
		svc, _, _, _ := newTestAuthService(t)

		claims := jwt.MapClaims{
			"sub":         uuid.New().String(),
			"dgb_address": "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
			"iat":         time.Now().Unix(),
			"exp":         time.Now().Add(15 * time.Minute).Unix(),
			"iss":         "digiauth",
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte("secret"))

		_, err := svc.ValidateAccessToken(tokenString)
		if err == nil {
			t.Error("ValidateAccessToken() expected error for wrong signing method")
		}
	})

	t.Run("malformed token", func(t *testing.T) {
		svc, _, _, _ := newTestAuthService(t)

		_, err := svc.ValidateAccessToken("not.a.valid.token")
		if err == nil {
			t.Error("ValidateAccessToken() expected error for malformed token")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		svc, _, _, _ := newTestAuthService(t)

		_, err := svc.ValidateAccessToken("")
		if err == nil {
			t.Error("ValidateAccessToken() expected error for empty token")
		}
	})
}

func TestAuthService_RefreshTokens(t *testing.T) {
	t.Run("not implemented", func(t *testing.T) {
		svc, _, _, _ := newTestAuthService(t)
		ctx := context.Background()

		_, err := svc.RefreshTokens(ctx, "some-refresh-token", "127.0.0.1", "TestAgent")
		if err == nil {
			t.Error("RefreshTokens() expected error (not implemented)")
		}
	})
}

// TestChallengeResponse verifies the response struct fields
func TestChallengeResponse(t *testing.T) {
	resp := ChallengeResponse{
		Nonce:     "abc123",
		URI:       "digiid://example.com/callback?x=abc123",
		ExpiresIn: 300,
	}

	if resp.Nonce != "abc123" {
		t.Errorf("ChallengeResponse.Nonce = %v, want abc123", resp.Nonce)
	}
	if resp.ExpiresIn != 300 {
		t.Errorf("ChallengeResponse.ExpiresIn = %v, want 300", resp.ExpiresIn)
	}
}

// --- Benchmarks ---

func BenchmarkCreateChallenge(b *testing.B) {
	userRepo := NewMockUserRepository()
	sessionRepo := NewMockSessionRepository()
	challengeStore := NewMockChallengeStore()
	cfg := newTestConfig()

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	svc := NewAuthService(userRepo, sessionRepo, challengeStore, cfg, privateKey, publicKey)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.CreateChallenge(ctx)
	}
}

func BenchmarkValidateAccessToken(b *testing.B) {
	userRepo := NewMockUserRepository()
	sessionRepo := NewMockSessionRepository()
	challengeStore := NewMockChallengeStore()
	cfg := newTestConfig()

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	svc := NewAuthService(userRepo, sessionRepo, challengeStore, cfg, privateKey, publicKey)

	// Pre-generate a valid token
	claims := jwt.MapClaims{
		"sub":         uuid.New().String(),
		"dgb_address": "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
		"iat":         time.Now().Unix(),
		"exp":         time.Now().Add(15 * time.Minute).Unix(),
		"iss":         "digiauth",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.ValidateAccessToken(tokenString)
	}
}
