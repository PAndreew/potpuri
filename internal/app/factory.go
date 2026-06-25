package app

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"potpuri/internal/ports"
	"potpuri/internal/security"
	"potpuri/internal/storage/postgres"
	"potpuri/internal/storage/r2"
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
	R2AccountID       string
	R2AccessKeyID     string
	R2SecretAccessKey string
	R2Bucket          string
}

func FactoryFromEnv() Factory {
	return Factory{
		Addr:              envDefault("POTPURI_ADDR", ":8080"),
		DatabaseURL:       os.Getenv("POTPURI_DATABASE_URL"),
		EncryptionKey:     os.Getenv("POTPURI_ENCRYPTION_KEY"),
		SessionSecret:     os.Getenv("POTPURI_SESSION_SECRET"),
		AllowRegistration: envBool("POTPURI_ALLOW_REGISTRATION", false),
		SecureCookies:     envBool("POTPURI_SECURE_COOKIES", true),
		R2AccountID:       os.Getenv("R2_ACCOUNT_ID"),
		R2AccessKeyID:     os.Getenv("R2_ACCESS_KEY_ID"),
		R2SecretAccessKey: os.Getenv("R2_SECRET_ACCESS_KEY"),
		R2Bucket:          os.Getenv("R2_BUCKET"),
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
	var blobContent ports.BlobContentStore
	if f.R2AccountID != "" && f.R2AccessKeyID != "" && f.R2SecretAccessKey != "" && f.R2Bucket != "" {
		blobContent = r2.Open(r2.Config{
			AccountID:       f.R2AccountID,
			AccessKeyID:     f.R2AccessKeyID,
			SecretAccessKey: f.R2SecretAccessKey,
			Bucket:          f.R2Bucket,
		})
	}
	svc := usecase.NewService(usecase.NewServiceParams{
		Users:       store,
		Items:       store,
		Blobs:       store,
		BlobContent: blobContent,
		Sessions:    store,
		Cipher:      cipher,
		Hasher:      security.NewPasswordHasher(),
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
