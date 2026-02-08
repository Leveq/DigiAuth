package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/kdogg/digiauth/internal/domain"
	"github.com/kdogg/digiauth/internal/domain/ports"
)

// UserService handles user profile operations.
type UserService struct {
	users ports.UserRepository
}

// NewUserService creates a new UserService.
func NewUserService(users ports.UserRepository) *UserService {
	return &UserService{users: users}
}

// GetProfile retrieves a user's profile by ID.
func (s *UserService) GetProfile(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	user, err := s.users.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	return user, nil
}

// UpdateProfile updates a user's display name, avatar, and bio.
func (s *UserService) UpdateProfile(ctx context.Context, id uuid.UUID, req *UpdateProfileRequest) (*domain.User, error) {
	user, err := s.users.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	if req.DisplayName != nil {
		if len(*req.DisplayName) > 100 {
			return nil, fmt.Errorf("display name must be 100 characters or less")
		}
		user.DisplayName = *req.DisplayName
	}
	if req.AvatarURL != nil {
		user.AvatarURL = *req.AvatarURL
	}
	if req.Bio != nil {
		if len(*req.Bio) > 500 {
			return nil, fmt.Errorf("bio must be 500 characters or less")
		}
		user.Bio = *req.Bio
	}

	updated, err := s.users.Update(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to update profile: %w", err)
	}

	return updated, nil
}

// UpdateProfileRequest holds optional fields for profile updates.
type UpdateProfileRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
	Bio         *string `json:"bio,omitempty"`
}
