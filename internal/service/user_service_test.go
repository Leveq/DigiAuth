package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kdogg/digiauth/internal/domain"
)

// --- Tests for UserService ---

func newTestUserService(t *testing.T) (*UserService, *MockUserRepository) {
	t.Helper()
	userRepo := NewMockUserRepository()
	svc := NewUserService(userRepo)
	return svc, userRepo
}

func TestNewUserService(t *testing.T) {
	svc, _ := newTestUserService(t)
	if svc == nil {
		t.Fatal("NewUserService returned nil")
	}
}

func TestUserService_GetProfile(t *testing.T) {
	t.Run("existing user", func(t *testing.T) {
		svc, userRepo := newTestUserService(t)
		ctx := context.Background()

		// Create a test user
		userID := uuid.New()
		expected := &domain.User{
			ID:          userID,
			DGBAddress:  "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
			DisplayName: "Test User",
			AvatarURL:   "https://example.com/avatar.png",
			Bio:         "Hello, I'm a test user",
			IsActive:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		userRepo.users[userID] = expected

		// Get profile
		user, err := svc.GetProfile(ctx, userID)
		if err != nil {
			t.Fatalf("GetProfile() error = %v", err)
		}
		if user.ID != userID {
			t.Errorf("GetProfile() ID = %v, want %v", user.ID, userID)
		}
		if user.DGBAddress != expected.DGBAddress {
			t.Errorf("GetProfile() DGBAddress = %v, want %v", user.DGBAddress, expected.DGBAddress)
		}
		if user.DisplayName != expected.DisplayName {
			t.Errorf("GetProfile() DisplayName = %v, want %v", user.DisplayName, expected.DisplayName)
		}
	})

	t.Run("non-existent user", func(t *testing.T) {
		svc, _ := newTestUserService(t)
		ctx := context.Background()

		_, err := svc.GetProfile(ctx, uuid.New())
		if err == nil {
			t.Error("GetProfile() expected error for non-existent user")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("GetProfile() error should contain 'not found', got: %v", err)
		}
	})

	t.Run("repository error", func(t *testing.T) {
		svc, userRepo := newTestUserService(t)
		ctx := context.Background()

		userRepo.GetByIDFunc = func(ctx context.Context, id uuid.UUID) (*domain.User, error) {
			return nil, errors.New("database connection failed")
		}

		_, err := svc.GetProfile(ctx, uuid.New())
		if err == nil {
			t.Error("GetProfile() expected error when repository fails")
		}
	})
}

func TestUserService_UpdateProfile(t *testing.T) {
	t.Run("update display name", func(t *testing.T) {
		svc, userRepo := newTestUserService(t)
		ctx := context.Background()

		userID := uuid.New()
		user := &domain.User{
			ID:         userID,
			DGBAddress: "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
			IsActive:   true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		userRepo.users[userID] = user

		newName := "New Display Name"
		req := &UpdateProfileRequest{
			DisplayName: &newName,
		}

		updated, err := svc.UpdateProfile(ctx, userID, req)
		if err != nil {
			t.Fatalf("UpdateProfile() error = %v", err)
		}
		if updated.DisplayName != newName {
			t.Errorf("UpdateProfile() DisplayName = %v, want %v", updated.DisplayName, newName)
		}
	})

	t.Run("update avatar URL", func(t *testing.T) {
		svc, userRepo := newTestUserService(t)
		ctx := context.Background()

		userID := uuid.New()
		user := &domain.User{
			ID:         userID,
			DGBAddress: "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
			IsActive:   true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		userRepo.users[userID] = user

		newAvatar := "https://example.com/new-avatar.png"
		req := &UpdateProfileRequest{
			AvatarURL: &newAvatar,
		}

		updated, err := svc.UpdateProfile(ctx, userID, req)
		if err != nil {
			t.Fatalf("UpdateProfile() error = %v", err)
		}
		if updated.AvatarURL != newAvatar {
			t.Errorf("UpdateProfile() AvatarURL = %v, want %v", updated.AvatarURL, newAvatar)
		}
	})

	t.Run("update bio", func(t *testing.T) {
		svc, userRepo := newTestUserService(t)
		ctx := context.Background()

		userID := uuid.New()
		user := &domain.User{
			ID:         userID,
			DGBAddress: "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
			IsActive:   true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		userRepo.users[userID] = user

		newBio := "This is my new bio"
		req := &UpdateProfileRequest{
			Bio: &newBio,
		}

		updated, err := svc.UpdateProfile(ctx, userID, req)
		if err != nil {
			t.Fatalf("UpdateProfile() error = %v", err)
		}
		if updated.Bio != newBio {
			t.Errorf("UpdateProfile() Bio = %v, want %v", updated.Bio, newBio)
		}
	})

	t.Run("update all fields", func(t *testing.T) {
		svc, userRepo := newTestUserService(t)
		ctx := context.Background()

		userID := uuid.New()
		user := &domain.User{
			ID:         userID,
			DGBAddress: "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
			IsActive:   true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		userRepo.users[userID] = user

		newName := "Full Update User"
		newAvatar := "https://example.com/full-avatar.png"
		newBio := "Fully updated bio"
		req := &UpdateProfileRequest{
			DisplayName: &newName,
			AvatarURL:   &newAvatar,
			Bio:         &newBio,
		}

		updated, err := svc.UpdateProfile(ctx, userID, req)
		if err != nil {
			t.Fatalf("UpdateProfile() error = %v", err)
		}
		if updated.DisplayName != newName {
			t.Errorf("UpdateProfile() DisplayName = %v, want %v", updated.DisplayName, newName)
		}
		if updated.AvatarURL != newAvatar {
			t.Errorf("UpdateProfile() AvatarURL = %v, want %v", updated.AvatarURL, newAvatar)
		}
		if updated.Bio != newBio {
			t.Errorf("UpdateProfile() Bio = %v, want %v", updated.Bio, newBio)
		}
	})

	t.Run("display name too long", func(t *testing.T) {
		svc, userRepo := newTestUserService(t)
		ctx := context.Background()

		userID := uuid.New()
		user := &domain.User{
			ID:         userID,
			DGBAddress: "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
			IsActive:   true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		userRepo.users[userID] = user

		longName := strings.Repeat("a", 101) // 101 characters
		req := &UpdateProfileRequest{
			DisplayName: &longName,
		}

		_, err := svc.UpdateProfile(ctx, userID, req)
		if err == nil {
			t.Error("UpdateProfile() expected error for too long display name")
		}
		if !strings.Contains(err.Error(), "100 characters") {
			t.Errorf("UpdateProfile() error should mention character limit, got: %v", err)
		}
	})

	t.Run("bio too long", func(t *testing.T) {
		svc, userRepo := newTestUserService(t)
		ctx := context.Background()

		userID := uuid.New()
		user := &domain.User{
			ID:         userID,
			DGBAddress: "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
			IsActive:   true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		userRepo.users[userID] = user

		longBio := strings.Repeat("a", 501) // 501 characters
		req := &UpdateProfileRequest{
			Bio: &longBio,
		}

		_, err := svc.UpdateProfile(ctx, userID, req)
		if err == nil {
			t.Error("UpdateProfile() expected error for too long bio")
		}
		if !strings.Contains(err.Error(), "500 characters") {
			t.Errorf("UpdateProfile() error should mention character limit, got: %v", err)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		svc, _ := newTestUserService(t)
		ctx := context.Background()

		newName := "Test"
		req := &UpdateProfileRequest{
			DisplayName: &newName,
		}

		_, err := svc.UpdateProfile(ctx, uuid.New(), req)
		if err == nil {
			t.Error("UpdateProfile() expected error for non-existent user")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("UpdateProfile() error should contain 'not found', got: %v", err)
		}
	})

	t.Run("empty update request", func(t *testing.T) {
		svc, userRepo := newTestUserService(t)
		ctx := context.Background()

		userID := uuid.New()
		originalName := "Original Name"
		user := &domain.User{
			ID:          userID,
			DGBAddress:  "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
			DisplayName: originalName,
			IsActive:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		userRepo.users[userID] = user

		req := &UpdateProfileRequest{} // No fields set

		updated, err := svc.UpdateProfile(ctx, userID, req)
		if err != nil {
			t.Fatalf("UpdateProfile() error = %v", err)
		}
		// Original values should be preserved
		if updated.DisplayName != originalName {
			t.Errorf("UpdateProfile() DisplayName = %v, want %v (unchanged)", updated.DisplayName, originalName)
		}
	})

	t.Run("max length display name (exactly 100)", func(t *testing.T) {
		svc, userRepo := newTestUserService(t)
		ctx := context.Background()

		userID := uuid.New()
		user := &domain.User{
			ID:         userID,
			DGBAddress: "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
			IsActive:   true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		userRepo.users[userID] = user

		maxName := strings.Repeat("a", 100) // Exactly 100 characters (should be allowed)
		req := &UpdateProfileRequest{
			DisplayName: &maxName,
		}

		updated, err := svc.UpdateProfile(ctx, userID, req)
		if err != nil {
			t.Fatalf("UpdateProfile() error = %v (100 chars should be allowed)", err)
		}
		if updated.DisplayName != maxName {
			t.Errorf("UpdateProfile() DisplayName length = %d, want 100", len(updated.DisplayName))
		}
	})

	t.Run("max length bio (exactly 500)", func(t *testing.T) {
		svc, userRepo := newTestUserService(t)
		ctx := context.Background()

		userID := uuid.New()
		user := &domain.User{
			ID:         userID,
			DGBAddress: "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
			IsActive:   true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		userRepo.users[userID] = user

		maxBio := strings.Repeat("a", 500) // Exactly 500 characters (should be allowed)
		req := &UpdateProfileRequest{
			Bio: &maxBio,
		}

		updated, err := svc.UpdateProfile(ctx, userID, req)
		if err != nil {
			t.Fatalf("UpdateProfile() error = %v (500 chars should be allowed)", err)
		}
		if updated.Bio != maxBio {
			t.Errorf("UpdateProfile() Bio length = %d, want 500", len(updated.Bio))
		}
	})
}

func TestUpdateProfileRequest(t *testing.T) {
	t.Run("nil fields by default", func(t *testing.T) {
		req := &UpdateProfileRequest{}
		if req.DisplayName != nil {
			t.Error("UpdateProfileRequest.DisplayName should be nil by default")
		}
		if req.AvatarURL != nil {
			t.Error("UpdateProfileRequest.AvatarURL should be nil by default")
		}
		if req.Bio != nil {
			t.Error("UpdateProfileRequest.Bio should be nil by default")
		}
	})
}

// --- Benchmarks ---

func BenchmarkGetProfile(b *testing.B) {
	userRepo := NewMockUserRepository()
	svc := NewUserService(userRepo)
	ctx := context.Background()

	userID := uuid.New()
	userRepo.users[userID] = &domain.User{
		ID:          userID,
		DGBAddress:  "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
		DisplayName: "Benchmark User",
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.GetProfile(ctx, userID)
	}
}

func BenchmarkUpdateProfile(b *testing.B) {
	userRepo := NewMockUserRepository()
	svc := NewUserService(userRepo)
	ctx := context.Background()

	userID := uuid.New()
	userRepo.users[userID] = &domain.User{
		ID:          userID,
		DGBAddress:  "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs",
		DisplayName: "Benchmark User",
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	newName := "Updated Name"
	req := &UpdateProfileRequest{
		DisplayName: &newName,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.UpdateProfile(ctx, userID, req)
	}
}
