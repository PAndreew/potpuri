package usecase

import (
	"context"
	"fmt"
	"strings"

	"potpuri/internal/domain"
	"potpuri/internal/ports"
)

const maxHarnessCredentials = 20

var harnessScopes = []string{"harness:heartbeat", "harness:claim", "harness:submit"}

type CreateHarnessCredentialInput struct {
	UserID   string
	Name     string
	Provider string
}

type CreateHarnessCredentialResult struct {
	Credential domain.HarnessCredential
	RawKey     string
}

type HarnessIdentity struct {
	CredentialID string                 `json:"credential_id"`
	UserID       string                 `json:"user_id"`
	Provider     domain.HarnessProvider `json:"provider"`
	Scopes       []string               `json:"scopes"`
}

func (s *Service) CreateHarnessCredential(ctx context.Context, input CreateHarnessCredentialInput) (CreateHarnessCredentialResult, error) {
	input.UserID = strings.TrimSpace(input.UserID)
	input.Name = strings.TrimSpace(input.Name)
	input.Provider = strings.TrimSpace(strings.ToLower(input.Provider))
	if input.UserID == "" {
		return CreateHarnessCredentialResult{}, ErrUnauthorized
	}
	if input.Name == "" {
		return CreateHarnessCredentialResult{}, fmt.Errorf("harness name is required")
	}
	if len(input.Name) > 80 {
		return CreateHarnessCredentialResult{}, fmt.Errorf("harness name must not exceed 80 characters")
	}
	provider := domain.HarnessProvider(input.Provider)
	if provider != domain.HarnessProviderCodex && provider != domain.HarnessProviderClaudeCode {
		return CreateHarnessCredentialResult{}, fmt.Errorf("unsupported harness provider")
	}
	if s.harnessCredentials == nil {
		return CreateHarnessCredentialResult{}, fmt.Errorf("harness credentials are not configured")
	}
	if _, err := s.users.FindUserByID(ctx, input.UserID); err != nil {
		return CreateHarnessCredentialResult{}, ErrUnauthorized
	}
	existing, err := s.harnessCredentials.ListHarnessCredentials(ctx, input.UserID)
	if err != nil {
		return CreateHarnessCredentialResult{}, err
	}
	active := 0
	for _, credential := range existing {
		if credential.RevokedAt == nil {
			active++
		}
	}
	if active >= maxHarnessCredentials {
		return CreateHarnessCredentialResult{}, fmt.Errorf("maximum of %d connected harnesses reached", maxHarnessCredentials)
	}
	rawKey := "phk_" + randomToken()
	credential := domain.HarnessCredential{
		ID: newID("hcr"), UserID: input.UserID, Name: input.Name, Provider: provider,
		KeyHint: rawKey[len(rawKey)-6:], CreatedAt: s.now().UTC(),
	}
	if err := s.harnessCredentials.CreateHarnessCredential(ctx, ports.StoredHarnessCredential{
		HarnessCredential: credential, TokenHash: hashToken(rawKey),
	}); err != nil {
		return CreateHarnessCredentialResult{}, err
	}
	return CreateHarnessCredentialResult{Credential: credential, RawKey: rawKey}, nil
}

func (s *Service) ListHarnessCredentials(ctx context.Context, userID string) ([]domain.HarnessCredential, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, ErrUnauthorized
	}
	if s.harnessCredentials == nil {
		return nil, fmt.Errorf("harness credentials are not configured")
	}
	stored, err := s.harnessCredentials.ListHarnessCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.HarnessCredential, len(stored))
	for i, credential := range stored {
		out[i] = credential.HarnessCredential
	}
	return out, nil
}

func (s *Service) RevokeHarnessCredential(ctx context.Context, userID, credentialID string) error {
	if strings.TrimSpace(userID) == "" {
		return ErrUnauthorized
	}
	if strings.TrimSpace(credentialID) == "" {
		return ErrNotFound
	}
	if s.harnessCredentials == nil {
		return fmt.Errorf("harness credentials are not configured")
	}
	return s.harnessCredentials.RevokeHarnessCredential(ctx, userID, credentialID, s.now().UTC())
}

func (s *Service) AuthenticateHarnessCredential(ctx context.Context, rawKey string) (HarnessIdentity, error) {
	if !strings.HasPrefix(rawKey, "phk_") || s.harnessCredentials == nil {
		return HarnessIdentity{}, ErrUnauthorized
	}
	credential, err := s.harnessCredentials.FindHarnessCredentialByHash(ctx, hashToken(rawKey))
	if err != nil || credential.RevokedAt != nil {
		return HarnessIdentity{}, ErrUnauthorized
	}
	if err := s.harnessCredentials.TouchHarnessCredential(ctx, credential.ID, s.now().UTC()); err != nil {
		return HarnessIdentity{}, err
	}
	return HarnessIdentity{
		CredentialID: credential.ID, UserID: credential.UserID, Provider: credential.Provider,
		Scopes: append([]string(nil), harnessScopes...),
	}, nil
}
