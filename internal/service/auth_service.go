package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/kdogg/digiauth/internal/config"
	"github.com/kdogg/digiauth/internal/crypto"
	"github.com/kdogg/digiauth/internal/domain"
	"github.com/kdogg/digiauth/internal/domain/ports"
)

// AuthService handles the Digi-ID authentication flow.
type AuthService struct {
	users      ports.UserRepository
	sessions   ports.SessionRepository
	challenges ports.ChallengeStore
	config     *config.Config
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewAuthService creates a new AuthService with all required dependencies.
func NewAuthService(
	users ports.UserRepository,
	sessions ports.SessionRepository,
	challenges ports.ChallengeStore,
	cfg *config.Config,
	privateKey *rsa.PrivateKey,
	publicKey *rsa.PublicKey,
) *AuthService {
	return &AuthService{
		users:      users,
		sessions:   sessions,
		challenges: challenges,
		config:     cfg,
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// CreateChallenge generates a new Digi-ID challenge for the client to display as a QR code.
func (s *AuthService) CreateChallenge(ctx context.Context) (*ChallengeResponse, error) {
	// Generate a cryptographically random nonce
	nonce, err := generateNonce(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Build the digiid:// URI
	uri, err := crypto.BuildChallengeURI(
		s.config.DigiID.CallbackURL,
		nonce,
		s.config.DigiID.Unsecure,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build challenge URI: %w", err)
	}

	// Store the challenge in Redis with TTL
	challenge := &domain.Challenge{
		Nonce:       nonce,
		CallbackURL: s.config.DigiID.CallbackURL,
		CreatedAt:   time.Now(),
	}
	if err := s.challenges.Create(ctx, challenge, s.config.DigiID.ChallengeTTL); err != nil {
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	return &ChallengeResponse{
		Nonce:     nonce,
		URI:       uri,
		ExpiresIn: int(s.config.DigiID.ChallengeTTL.Seconds()),
	}, nil
}

// VerifyCallback processes the wallet's callback after signing the challenge.
// This is the core of the Digi-ID protocol implementation.
func (s *AuthService) VerifyCallback(ctx context.Context, callback *domain.DigiIDCallback, ipAddress, userAgent string) error {
	// 1. Extract the nonce from the URI
	nonce, err := crypto.ExtractNonce(callback.URI)
	if err != nil {
		return fmt.Errorf("invalid callback URI: %w", err)
	}

	// 2. Retrieve and validate the challenge exists (not expired/consumed)
	challenge, err := s.challenges.Get(ctx, nonce)
	if err != nil {
		return fmt.Errorf("failed to retrieve challenge: %w", err)
	}
	if challenge == nil {
		return fmt.Errorf("challenge not found or expired")
	}

	// 3. Validate the callback URI matches our expected callback
	if err := crypto.ValidateCallbackURI(
		callback.URI,
		challenge.CallbackURL,
		s.config.DigiID.Unsecure,
	); err != nil {
		return fmt.Errorf("callback URI validation failed: %w", err)
	}

	// 4. Verify the ECDSA signature against the DigiByte address
	if err := crypto.VerifySignature(callback.Address, callback.Signature, callback.URI); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// 5. Signature is valid — find or create the user
	user, err := s.findOrCreateUser(ctx, callback.Address)
	if err != nil {
		return fmt.Errorf("failed to find/create user: %w", err)
	}

	// 6. Update last login timestamp
	if err := s.users.UpdateLastLogin(ctx, user.ID, time.Now()); err != nil {
		// Non-fatal — log but don't fail auth
		fmt.Printf("WARN: failed to update last login for user %s: %v\n", user.ID, err)
	}

	// 7. Issue tokens
	tokenPair, err := s.issueTokens(ctx, user, ipAddress, userAgent)
	if err != nil {
		return fmt.Errorf("failed to issue tokens: %w", err)
	}

	// 8. Store the result for client polling and consume the challenge
	result := &domain.ChallengeResult{
		Nonce:        nonce,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
		UserID:       user.ID.String(),
	}
	if err := s.challenges.SetResult(ctx, nonce, result, 2*time.Minute); err != nil {
		return fmt.Errorf("failed to store auth result: %w", err)
	}

	// 9. Delete the original challenge (consumed)
	if err := s.challenges.Delete(ctx, nonce); err != nil {
		fmt.Printf("WARN: failed to delete consumed challenge %s: %v\n", nonce, err)
	}

	return nil
}

// PollResult checks if a challenge has been completed and returns the tokens.
func (s *AuthService) PollResult(ctx context.Context, nonce string) (*domain.ChallengeResult, error) {
	return s.challenges.GetResult(ctx, nonce)
}

// RefreshTokens exchanges a refresh token for a new token pair.
func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken, ipAddress, userAgent string) (*domain.TokenPair, error) {
	// Hash the provided refresh token
	hash := hashToken(refreshToken)

	// TODO: Look up session by refresh token hash, validate, rotate, and issue new pair
	// For now, return a placeholder error
	_ = hash
	return nil, fmt.Errorf("refresh token flow not yet implemented")
}

// ValidateAccessToken parses and validates a JWT access token.
func (s *AuthService) ValidateAccessToken(tokenString string) (*domain.TokenClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	userID, err := uuid.Parse(claims["sub"].(string))
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in token: %w", err)
	}

	return &domain.TokenClaims{
		UserID:     userID,
		DGBAddress: claims["dgb_address"].(string),
	}, nil
}

// --- Private helpers ---

func (s *AuthService) findOrCreateUser(ctx context.Context, dgbAddress string) (*domain.User, error) {
	// Try to find existing user
	user, err := s.users.GetByDGBAddress(ctx, dgbAddress)
	if err == nil && user != nil {
		return user, nil
	}

	// Create new user (auto-register on first auth)
	newUser := &domain.User{
		ID:         uuid.New(),
		DGBAddress: dgbAddress,
		IsActive:   true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	created, err := s.users.Create(ctx, newUser)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return created, nil
}

func (s *AuthService) issueTokens(ctx context.Context, user *domain.User, ipAddress, userAgent string) (*domain.TokenPair, error) {
	now := time.Now()
	accessExpiry := now.Add(s.config.Auth.AccessTokenTTL)

	// Build JWT access token
	accessClaims := jwt.MapClaims{
		"sub":         user.ID.String(),
		"dgb_address": user.DGBAddress,
		"iat":         now.Unix(),
		"exp":         accessExpiry.Unix(),
		"iss":         "digiauth",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate opaque refresh token
	refreshTokenRaw, err := generateNonce(48)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store session with hashed refresh token
	session := &domain.Session{
		ID:               uuid.New(),
		UserID:           user.ID,
		RefreshTokenHash: hashToken(refreshTokenRaw),
		IPAddress:        ipAddress,
		UserAgent:        userAgent,
		CreatedAt:        now,
		ExpiresAt:        now.Add(s.config.Auth.RefreshTokenTTL),
	}

	if _, err := s.sessions.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &domain.TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenRaw,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.config.Auth.AccessTokenTTL.Seconds()),
	}, nil
}

// --- Utility functions ---

// generateNonce creates a cryptographically random hex-encoded nonce.
func generateNonce(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hashToken returns the SHA-256 hex digest of a token string.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// --- Response types ---

// ChallengeResponse is returned to the client when a new challenge is created.
type ChallengeResponse struct {
	Nonce     string `json:"nonce"`
	URI       string `json:"uri"`
	ExpiresIn int    `json:"expires_in"`
}
