package domain

import (
	"time"

	"github.com/google/uuid"
)

// User represents an authenticated DigiAuth user.
// The DGB address is the identity anchor — no passwords ever.
type User struct {
	ID          uuid.UUID  `json:"id"`
	DGBAddress  string     `json:"dgb_address"`
	DisplayName string     `json:"display_name,omitempty"`
	AvatarURL   string     `json:"avatar_url,omitempty"`
	Bio         string     `json:"bio,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	IsActive    bool       `json:"is_active"`
}

// Session represents an active refresh token session.
type Session struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	RefreshTokenHash string     `json:"-"` // Never expose hash
	IPAddress        string     `json:"ip_address"`
	UserAgent        string     `json:"user_agent"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
}

// IsExpired returns true if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsRevoked returns true if the session has been explicitly revoked.
func (s *Session) IsRevoked() bool {
	return s.RevokedAt != nil
}

// IsValid returns true if the session is active, not expired, and not revoked.
func (s *Session) IsValid() bool {
	return !s.IsExpired() && !s.IsRevoked()
}

// Challenge represents a Digi-ID authentication challenge stored in Redis.
type Challenge struct {
	Nonce       string    `json:"nonce"`
	CallbackURL string    `json:"callback_url"`
	ClientID    string    `json:"client_id,omitempty"` // For OAuth flow
	CreatedAt   time.Time `json:"created_at"`
}

// ChallengeResult holds the authentication result after a wallet signs the challenge.
type ChallengeResult struct {
	Nonce        string `json:"nonce"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // Seconds until access token expires
	UserID       string `json:"user_id"`
}

// TokenPair holds access and refresh tokens issued after authentication.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// TokenClaims represents the JWT claims embedded in access tokens.
type TokenClaims struct {
	UserID     uuid.UUID `json:"sub"`
	DGBAddress string    `json:"dgb_address"`
	IssuedAt   time.Time `json:"iat"`
	ExpiresAt  time.Time `json:"exp"`
}

// DigiIDCallback is the payload sent by the DigiByte wallet after signing.
type DigiIDCallback struct {
	Address   string `json:"address"`
	URI       string `json:"uri"`
	Signature string `json:"signature"`
}
