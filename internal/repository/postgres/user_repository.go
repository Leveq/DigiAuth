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

// UserRepository implements ports.UserRepository using PostgreSQL.
type UserRepository struct {
	pool *pgxpool.Pool
}

// NewUserRepository creates a new PostgreSQL-backed user repository.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

// Create inserts a new user and returns the created record.
func (r *UserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	query := `
		INSERT INTO users (id, dgb_address, display_name, avatar_url, bio, created_at, updated_at, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, dgb_address, display_name, avatar_url, bio, created_at, updated_at, last_login_at, is_active`

	var created domain.User
	err := r.pool.QueryRow(ctx, query,
		user.ID, user.DGBAddress, user.DisplayName, user.AvatarURL,
		user.Bio, user.CreatedAt, user.UpdatedAt, user.IsActive,
	).Scan(
		&created.ID, &created.DGBAddress, &created.DisplayName, &created.AvatarURL,
		&created.Bio, &created.CreatedAt, &created.UpdatedAt, &created.LastLoginAt, &created.IsActive,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &created, nil
}

// GetByID retrieves a user by internal UUID.
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, dgb_address, display_name, avatar_url, bio, created_at, updated_at, last_login_at, is_active
		FROM users
		WHERE id = $1 AND is_active = TRUE`

	var user domain.User
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.DGBAddress, &user.DisplayName, &user.AvatarURL,
		&user.Bio, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt, &user.IsActive,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetByDGBAddress retrieves a user by their DigiByte address.
func (r *UserRepository) GetByDGBAddress(ctx context.Context, address string) (*domain.User, error) {
	query := `
		SELECT id, dgb_address, display_name, avatar_url, bio, created_at, updated_at, last_login_at, is_active
		FROM users
		WHERE dgb_address = $1 AND is_active = TRUE`

	var user domain.User
	err := r.pool.QueryRow(ctx, query, address).Scan(
		&user.ID, &user.DGBAddress, &user.DisplayName, &user.AvatarURL,
		&user.Bio, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt, &user.IsActive,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user not found for address: %s", address)
		}
		return nil, fmt.Errorf("failed to get user by address: %w", err)
	}

	return &user, nil
}

// Update modifies a user's profile fields.
func (r *UserRepository) Update(ctx context.Context, user *domain.User) (*domain.User, error) {
	query := `
		UPDATE users
		SET display_name = $2, avatar_url = $3, bio = $4
		WHERE id = $1 AND is_active = TRUE
		RETURNING id, dgb_address, display_name, avatar_url, bio, created_at, updated_at, last_login_at, is_active`

	var updated domain.User
	err := r.pool.QueryRow(ctx, query,
		user.ID, user.DisplayName, user.AvatarURL, user.Bio,
	).Scan(
		&updated.ID, &updated.DGBAddress, &updated.DisplayName, &updated.AvatarURL,
		&updated.Bio, &updated.CreatedAt, &updated.UpdatedAt, &updated.LastLoginAt, &updated.IsActive,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %s", user.ID)
		}
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &updated, nil
}

// UpdateLastLogin sets the last_login_at timestamp.
func (r *UserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID, loginTime time.Time) error {
	query := `UPDATE users SET last_login_at = $2 WHERE id = $1`

	tag, err := r.pool.Exec(ctx, query, id, loginTime)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", id)
	}

	return nil
}
