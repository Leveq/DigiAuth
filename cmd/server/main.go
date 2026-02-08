package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/kdogg/digiauth/internal/config"
	"github.com/kdogg/digiauth/internal/handler"
	"github.com/kdogg/digiauth/internal/middleware"
	"github.com/kdogg/digiauth/internal/repository/postgres"
	redisrepo "github.com/kdogg/digiauth/internal/repository/redis"
	"github.com/kdogg/digiauth/internal/service"
)

func main() {
	ctx := context.Background()

	// ─── Load Configuration ─────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("DigiAuth starting in %s mode on %s:%d", cfg.Server.Env, cfg.Server.Host, cfg.Server.Port)

	// ─── Load RSA Keys for JWT ──────────────────────────────────────
	privateKey, publicKey, err := loadRSAKeys(cfg.Auth.JWTPrivateKey, cfg.Auth.JWTPublicKey)
	if err != nil {
		log.Fatalf("Failed to load RSA keys: %v\nRun 'make keys' to generate them.", err)
	}
	log.Println("RSA keys loaded successfully")

	// ─── Connect to PostgreSQL ──────────────────────────────────────
	pgPool, err := postgres.NewPool(ctx, cfg.Database.DSN())
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v\nRun 'make db-up' to start the database.", err)
	}
	defer pgPool.Close()
	log.Println("Connected to PostgreSQL")

	// ─── Connect to Redis ───────────────────────────────────────────
	redisClient, err := redisrepo.NewClient(ctx, cfg.Redis.Addr(), cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v\nRun 'make db-up' to start Redis.", err)
	}
	defer redisClient.Close()
	log.Println("Connected to Redis")

	// ─── Initialize Repositories ────────────────────────────────────
	userRepo := postgres.NewUserRepository(pgPool)
	sessionRepo := postgres.NewSessionRepository(pgPool)
	challengeStore := redisrepo.NewChallengeStore(redisClient)

	// ─── Initialize Services ────────────────────────────────────────
	authService := service.NewAuthService(userRepo, sessionRepo, challengeStore, cfg, privateKey, publicKey)
	userService := service.NewUserService(userRepo)

	// ─── Initialize Handlers ────────────────────────────────────────
	authHandler := handler.NewAuthHandler(authService)
	userHandler := handler.NewUserHandler(userService)

	// ─── Build Router ───────────────────────────────────────────────
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "https://digiauth.leveq.dev"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"digiauth","version":"0.1.0"}`))
	})

	// API v1 routes
	r.Route("/api/v1", func(r chi.Router) {
		// Public auth routes — no JWT required
		r.Mount("/auth", authHandler.Routes())

		// Protected routes — JWT required
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuth(authService))
			r.Mount("/users", userHandler.Routes())
		})

		// Demo endpoints
		r.Get("/demo/public", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"message":"This endpoint is public. No authentication required.","data":{"blockchain":"DigiByte","protocol":"Digi-ID"}}`))
		})
		r.With(middleware.JWTAuth(authService)).Get("/demo/protected", func(w http.ResponseWriter, r *http.Request) {
			claims := middleware.GetClaims(r.Context())
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(fmt.Sprintf(`{"message":"You are authenticated!","user_id":"%s","dgb_address":"%s"}`, claims.UserID, claims.DGBAddress)))
		})
	})

	// ─── Start Server ───────────────────────────────────────────────
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigChan

		log.Printf("Received signal %v, shutting down gracefully...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Fatalf("Server forced to shutdown: %v", err)
		}
	}()

	log.Printf("DigiAuth server listening on %s", srv.Addr)
	log.Printf("  Health:    http://localhost:%d/health", cfg.Server.Port)
	log.Printf("  Challenge: POST http://localhost:%d/api/v1/auth/challenge", cfg.Server.Port)
	log.Printf("  Demo:      GET  http://localhost:%d/api/v1/demo/public", cfg.Server.Port)

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}

	log.Println("DigiAuth server stopped")
}

// loadRSAKeys reads PEM-encoded RSA key files for JWT signing/verification.
func loadRSAKeys(privatePath, publicPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privPEM, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key %s: %w", privatePath, err)
	}

	privBlock, _ := pem.Decode(privPEM)
	if privBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		key, err2 := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
		if err2 != nil {
			return nil, nil, fmt.Errorf("failed to parse private key: PKCS1=%v, PKCS8=%v", err, err2)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("private key is not RSA")
		}
	}

	pubPEM, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key %s: %w", publicPath, err)
	}

	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode public key PEM")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("public key is not RSA")
	}

	return privateKey, publicKey, nil
}
