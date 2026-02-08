package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all application configuration.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	Auth     AuthConfig
	DigiID   DigiIDConfig
}

type ServerConfig struct {
	Host string
	Port int
	Env  string // "development", "production"
}

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

type AuthConfig struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	JWTPrivateKey   string // Path to RSA private key PEM
	JWTPublicKey    string // Path to RSA public key PEM
}

type DigiIDConfig struct {
	CallbackURL  string // e.g., "https://digiauth.leveq.dev/api/v1/auth/callback"
	ChallengeTTL time.Duration
	Unsecure     bool // true for local dev (http instead of https)
}

// Load reads configuration from environment variables with .env fallback.
func Load() (*Config, error) {
	// Load .env file if it exists (silently ignore if missing)
	_ = godotenv.Load()

	cfg := &Config{
		Server: ServerConfig{
			Host: getEnv("SERVER_HOST", "0.0.0.0"),
			Port: getEnvInt("SERVER_PORT", 8080),
			Env:  getEnv("SERVER_ENV", "development"),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnvInt("DB_PORT", 5432),
			User:     getEnv("DB_USER", "digiauth"),
			Password: getEnv("DB_PASSWORD", "digiauth"),
			DBName:   getEnv("DB_NAME", "digiauth"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnvInt("REDIS_PORT", 6379),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvInt("REDIS_DB", 0),
		},
		Auth: AuthConfig{
			AccessTokenTTL:  getEnvDuration("AUTH_ACCESS_TOKEN_TTL", 15*time.Minute),
			RefreshTokenTTL: getEnvDuration("AUTH_REFRESH_TOKEN_TTL", 30*24*time.Hour),
			JWTPrivateKey:   getEnv("AUTH_JWT_PRIVATE_KEY", "keys/private.pem"),
			JWTPublicKey:    getEnv("AUTH_JWT_PUBLIC_KEY", "keys/public.pem"),
		},
		DigiID: DigiIDConfig{
			CallbackURL:  getEnv("DIGIID_CALLBACK_URL", "http://localhost:8080/api/v1/auth/callback"),
			ChallengeTTL: getEnvDuration("DIGIID_CHALLENGE_TTL", 5*time.Minute),
			Unsecure:     getEnvBool("DIGIID_UNSECURE", true),
		},
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	if c.DigiID.CallbackURL == "" {
		return fmt.Errorf("DIGIID_CALLBACK_URL is required")
	}
	return nil
}

// DSN returns the PostgreSQL connection string.
func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User, d.Password, d.Host, d.Port, d.DBName, d.SSLMode,
	)
}

// Addr returns the Redis address string.
func (r *RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

// --- Helpers ---

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if val, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(val); err == nil {
			return b
		}
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if val, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return fallback
}
