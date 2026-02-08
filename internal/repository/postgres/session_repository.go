package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kdogg/digiauth/internal/domain"
)

// SessionRepository implements ports.SessionRepository using PostgreSQL.
type SessionRepository struct {
	pool *pgxpool.Pool
}

// NewSessionRepository creates a new PostgreSQL-backed session repository.
func NewSessionRepository(pool *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{pool: pool}
}

// Create inserts a new session.
func (r *SessionRepository) Create(ctx context.Context, session *domain.Session) (*domain.Session, error) {
	query := `
		INSERT INTO sessions (id, user_id, refresh_token_hash, ip_address, user_agent, created_at, expires_at)
		VALUES ($1, $2, $3, $4::inet, $5, $6, $7)
		RETURNING id, user_id, refresh_token_hash, ip_address, user_agent, created_at, expires_at, revoked_at`

	var created domain.Session
	err := r.pool.QueryRow(ctx, query,
		session.ID, session.UserID, session.RefreshTokenHash,
		session.IPAddress, session.UserAgent, session.CreatedAt, session.ExpiresAt,
	).Scan(
		&created.ID, &created.UserID, &created.RefreshTokenHash,
		&created.IPAddress, &created.UserAgent, &created.CreatedAt, &created.ExpiresAt, &created.RevokedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &created, nil
}

// GetByID retrieves a session by ID.
func (r *SessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, ip_address, user_agent, created_at, expires_at, revoked_at
		FROM sessions
		WHERE id = $1`

	var session domain.Session
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&session.ID, &session.UserID, &session.RefreshTokenHash,
		&session.IPAddress, &session.UserAgent, &session.CreatedAt, &session.ExpiresAt, &session.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("session not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

// GetByUserID retrieves all active (non-revoked, non-expired) sessions for a user.
func (r *SessionRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, ip_address, user_agent, created_at, expires_at, revoked_at
		FROM sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*domain.Session
	for rows.Next() {
		var s domain.Session
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.RefreshTokenHash,
			&s.IPAddress, &s.UserAgent, &s.CreatedAt, &s.ExpiresAt, &s.RevokedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, &s)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating sessions: %w", err)
	}

	return sessions, nil
}

// Revoke marks a session as revoked by setting revoked_at.
func (r *SessionRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE sessions SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, id, time.Now())
	if err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("session not found or already revoked: %s", id)
	}

	return nil
}

// RevokeAllForUser revokes all active sessions for a given user.
func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE sessions SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`

	_, err := r.pool.Exec(ctx, query, userID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to revoke all sessions: %w", err)
	}

	return nil
}

// DeleteExpired removes sessions that have expired. Returns the count of deleted rows.
func (r *SessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM sessions WHERE expires_at < NOW()`

	tag, err := r.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	return tag.RowsAffected(), nil
}
