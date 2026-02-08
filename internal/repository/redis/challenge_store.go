package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/kdogg/digiauth/internal/domain"
)

const (
	challengePrefix = "digiauth:challenge:"
	resultPrefix    = "digiauth:result:"
	rateLimitPrefix = "digiauth:ratelimit:"
)

// ChallengeStore implements ports.ChallengeStore using Redis.
type ChallengeStore struct {
	client *redis.Client
}

// NewChallengeStore creates a new Redis-backed challenge store.
func NewChallengeStore(client *redis.Client) *ChallengeStore {
	return &ChallengeStore{client: client}
}

// Create stores a new challenge with automatic TTL expiry.
func (s *ChallengeStore) Create(ctx context.Context, challenge *domain.Challenge, ttl time.Duration) error {
	data, err := json.Marshal(challenge)
	if err != nil {
		return fmt.Errorf("failed to marshal challenge: %w", err)
	}

	key := challengePrefix + challenge.Nonce
	if err := s.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store challenge: %w", err)
	}

	return nil
}

// Get retrieves a challenge by nonce. Returns nil if expired or not found.
func (s *ChallengeStore) Get(ctx context.Context, nonce string) (*domain.Challenge, error) {
	key := challengePrefix + nonce
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Expired or doesn't exist
		}
		return nil, fmt.Errorf("failed to get challenge: %w", err)
	}

	var challenge domain.Challenge
	if err := json.Unmarshal(data, &challenge); err != nil {
		return nil, fmt.Errorf("failed to unmarshal challenge: %w", err)
	}

	return &challenge, nil
}

// Delete removes a challenge (consumed after successful verification).
func (s *ChallengeStore) Delete(ctx context.Context, nonce string) error {
	key := challengePrefix + nonce
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete challenge: %w", err)
	}
	return nil
}

// SetResult stores the authentication result for client polling.
func (s *ChallengeStore) SetResult(ctx context.Context, nonce string, result *domain.ChallengeResult, ttl time.Duration) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	key := resultPrefix + nonce
	if err := s.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store result: %w", err)
	}

	return nil
}

// GetResult retrieves the auth result for a given nonce (used by polling).
func (s *ChallengeStore) GetResult(ctx context.Context, nonce string) (*domain.ChallengeResult, error) {
	key := resultPrefix + nonce
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Not ready yet
		}
		return nil, fmt.Errorf("failed to get result: %w", err)
	}

	var result domain.ChallengeResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// RateLimiter implements ports.RateLimiter using Redis.
type RateLimiter struct {
	client *redis.Client
}

// NewRateLimiter creates a new Redis-backed rate limiter.
func NewRateLimiter(client *redis.Client) *RateLimiter {
	return &RateLimiter{client: client}
}

// Allow checks if the action is allowed within the rate limit window.
// Uses a simple sliding window counter.
func (rl *RateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	fullKey := rateLimitPrefix + key

	// Increment the counter
	count, err := rl.client.Incr(ctx, fullKey).Result()
	if err != nil {
		return false, fmt.Errorf("failed to increment rate limit counter: %w", err)
	}

	// Set TTL on first request in the window
	if count == 1 {
		if err := rl.client.Expire(ctx, fullKey, window).Err(); err != nil {
			return false, fmt.Errorf("failed to set rate limit expiry: %w", err)
		}
	}

	return count <= int64(limit), nil
}
