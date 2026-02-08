package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// NewClient creates a configured Redis client and verifies connectivity.
func NewClient(ctx context.Context, addr, password string, db int) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,

		// Connection pool
		PoolSize:     20,
		MinIdleConns: 5,
	})

	// Verify connectivity
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping Redis at %s: %w", addr, err)
	}

	return client, nil
}
