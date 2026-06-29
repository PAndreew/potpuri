package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"potpuri/internal/email"
	"potpuri/internal/fetch"
	"potpuri/internal/ports"
	"potpuri/internal/security"
	"potpuri/internal/storage/postgres"
	"potpuri/internal/storage/r2"
	"potpuri/internal/usecase"
	"potpuri/internal/web"
)

type Factory struct {
	Addr                string
	DatabaseURL         string
	EncryptionKey       string
	EncryptionKeyURL    string
	EncryptionKeyToken  string
	SessionSecret       string
	AllowRegistration   bool
	SecureCookies       bool
	AdminEmail          string
	PublicURL           string
	StripeSecretKey     string
	StripePriceID       string
	StripeWebhookSecret string
	R2AccountID         string
	R2AccessKeyID       string
	R2SecretAccessKey   string
	R2Bucket            string
	ResendAPIKey        string
	ResendFromEmail     string
	FeedServiceToken    string
	FeedSigningSecret   string
	FeedMCPURL          string
}

func FactoryFromEnv() Factory {
	return Factory{
		Addr:                envDefault("POTPURI_ADDR", ":8080"),
		DatabaseURL:         os.Getenv("POTPURI_DATABASE_URL"),
		EncryptionKey:       os.Getenv("POTPURI_ENCRYPTION_KEY"),
		EncryptionKeyURL:    os.Getenv("POTPURI_ENCRYPTION_KEY_URL"),
		EncryptionKeyToken:  os.Getenv("POTPURI_ENCRYPTION_KEY_BEARER_TOKEN"),
		SessionSecret:       os.Getenv("POTPURI_SESSION_SECRET"),
		AllowRegistration:   envBool("POTPURI_ALLOW_REGISTRATION", false),
		SecureCookies:       envBool("POTPURI_SECURE_COOKIES", true),
		AdminEmail:          os.Getenv("POTPURI_ADMIN_EMAIL"),
		PublicURL:           os.Getenv("POTPURI_PUBLIC_URL"),
		StripeSecretKey:     os.Getenv("STRIPE_SECRET_KEY"),
		StripePriceID:       os.Getenv("STRIPE_PRICE_ID"),
		StripeWebhookSecret: os.Getenv("STRIPE_WEBHOOK_SECRET"),
		R2AccountID:         os.Getenv("R2_ACCOUNT_ID"),
		R2AccessKeyID:       os.Getenv("R2_ACCESS_KEY_ID"),
		R2SecretAccessKey:   os.Getenv("R2_SECRET_ACCESS_KEY"),
		R2Bucket:            os.Getenv("R2_BUCKET"),
		ResendAPIKey:        os.Getenv("RESEND_API_KEY"),
		ResendFromEmail:     envDefault("RESEND_FROM_EMAIL", "noreply@potpuri.app"),
		FeedServiceToken:    os.Getenv("POTPURI_FEED_SERVICE_TOKEN"),
		FeedSigningSecret:   os.Getenv("POTPURI_FEED_SIGNING_SECRET"),
		FeedMCPURL:          os.Getenv("POTPURI_FEED_MCP_URL"),
	}
}

func (f Factory) Build(ctx context.Context) (*http.Server, func() error, error) {
	if f.DatabaseURL == "" {
		return nil, nil, fmt.Errorf("POTPURI_DATABASE_URL is required")
	}
	encryptionKey, err := f.loadEncryptionKey(ctx)
	if err != nil {
		return nil, nil, err
	}
	store, err := postgres.Open(f.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	cipher, err := security.NewCipherFromBase64(encryptionKey)
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
	var mailer ports.Mailer
	if f.ResendAPIKey != "" {
		mailer = &email.ResendMailer{APIKey: f.ResendAPIKey, FromEmail: f.ResendFromEmail}
	}
	var feedCredentials ports.FeedCredentialIssuer
	if f.FeedSigningSecret != "" {
		feedCredentials, err = security.NewFeedCredentialIssuer(f.FeedSigningSecret)
		if err != nil {
			_ = store.Close()
			return nil, nil, err
		}
	}
	svc := usecase.NewService(usecase.NewServiceParams{
		Users:              store,
		Items:              store,
		Blobs:              store,
		BlobContent:        blobContent,
		Sessions:           store,
		EmailVerifications: store,
		SecretShares:       store,
		Fetcher:            &fetch.HTTPFetcher{},
		Mailer:             mailer,
		Cipher:             cipher,
		Hasher:             security.NewPasswordHasher(),
		PublicURL:          f.PublicURL,
		FeedCredentials:    feedCredentials,
		HarnessCredentials: store,
	})
	handler := web.NewServerWithConfig(svc, web.Config{
		AllowRegistration:   f.AllowRegistration,
		SecureCookies:       f.SecureCookies,
		AdminEmail:          f.AdminEmail,
		StripeSecretKey:     f.StripeSecretKey,
		StripePriceID:       f.StripePriceID,
		StripeWebhookSecret: f.StripeWebhookSecret,
		PublicURL:           f.PublicURL,
		FeedServiceToken:    f.FeedServiceToken,
		FeedMCPURL:          f.FeedMCPURL,
	})
	server := &http.Server{Addr: f.Addr, Handler: handler.Routes()}
	return server, store.Close, nil
}

func (f Factory) loadEncryptionKey(ctx context.Context) (string, error) {
	if strings.TrimSpace(f.EncryptionKey) != "" {
		return strings.TrimSpace(f.EncryptionKey), nil
	}
	if strings.TrimSpace(f.EncryptionKeyURL) == "" {
		return "", fmt.Errorf("POTPURI_ENCRYPTION_KEY or POTPURI_ENCRYPTION_KEY_URL is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.EncryptionKeyURL, nil)
	if err != nil {
		return "", err
	}
	if f.EncryptionKeyToken != "" {
		req.Header.Set("Authorization", "Bearer "+f.EncryptionKeyToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("encryption key fetch failed with HTTP %d", resp.StatusCode)
	}
	key := strings.TrimSpace(string(body))
	if key == "" {
		return "", fmt.Errorf("encryption key endpoint returned an empty response")
	}
	return key, nil
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
