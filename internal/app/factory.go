package app

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"potpuri/internal/security"
	"potpuri/internal/storage/postgres"
	"potpuri/internal/usecase"
	"potpuri/internal/web"
)

type Factory struct {
	Addr              string
	DatabaseURL       string
	EncryptionKey     string
	SessionSecret     string
	AllowRegistration bool
	SecureCookies     bool
}

func FactoryFromEnv() Factory {
	return Factory{
		Addr:              envDefault("POTPURI_ADDR", ":8080"),
		DatabaseURL:       os.Getenv("POTPURI_DATABASE_URL"),
		EncryptionKey:     os.Getenv("POTPURI_ENCRYPTION_KEY"),
		SessionSecret:     os.Getenv("POTPURI_SESSION_SECRET"),
		AllowRegistration: envBool("POTPURI_ALLOW_REGISTRATION", false),
		SecureCookies:     envBool("POTPURI_SECURE_COOKIES", true),
	}
}

func (f Factory) Build(ctx context.Context) (*http.Server, func() error, error) {
	if f.DatabaseURL == "" {
		return nil, nil, fmt.Errorf("POTPURI_DATABASE_URL is required")
	}
	if f.EncryptionKey == "" {
		return nil, nil, fmt.Errorf("POTPURI_ENCRYPTION_KEY is required")
	}
	store, err := postgres.Open(f.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	cipher, err := security.NewCipherFromBase64(f.EncryptionKey)
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	svc := usecase.NewService(usecase.NewServiceParams{
		Users:    store,
		Items:    store,
		Blobs:    store,
		Sessions: store,
		Cipher:   cipher,
		Hasher:   security.NewPasswordHasher(),
	})
	handler := web.NewServerWithConfig(svc, web.Config{
		AllowRegistration: f.AllowRegistration,
		SecureCookies:     f.SecureCookies,
	})
	server := &http.Server{Addr: f.Addr, Handler: handler.Routes()}
	return server, store.Close, nil
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "TRUE", "yes", "YES", "on", "ON":
		return true
	case "0", "false", "FALSE", "no", "NO", "off", "OFF":
		return false
	default:
		return fallback
	}
}
