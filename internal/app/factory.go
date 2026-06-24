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
	Addr          string
	DatabaseURL   string
	EncryptionKey string
	SessionSecret string
}

func FactoryFromEnv() Factory {
	return Factory{
		Addr:          envDefault("POTPURI_ADDR", ":8080"),
		DatabaseURL:   os.Getenv("POTPURI_DATABASE_URL"),
		EncryptionKey: os.Getenv("POTPURI_ENCRYPTION_KEY"),
		SessionSecret: os.Getenv("POTPURI_SESSION_SECRET"),
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
		Sessions: store,
		Cipher:   cipher,
		Hasher:   security.NewPasswordHasher(),
	})
	handler := web.NewServer(svc)
	server := &http.Server{Addr: f.Addr, Handler: handler.Routes()}
	return server, store.Close, nil
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
