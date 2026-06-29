package usecase_test

import (
	"context"
	"errors"
	"testing"

	"potpuri/internal/usecase"
)

func TestUserCreatesSeparateScopedHarnessCredentials(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newFeedTestService(t)
	user, _ := svc.Register(ctx, usecase.RegisterInput{Email: "harness-owner@example.com", Password: "correct horse"})

	codex, err := svc.CreateHarnessCredential(ctx, usecase.CreateHarnessCredentialInput{
		UserID: user.ID, Name: "Laptop Codex", Provider: "codex",
	})
	if err != nil {
		t.Fatal(err)
	}
	claude, err := svc.CreateHarnessCredential(ctx, usecase.CreateHarnessCredentialInput{
		UserID: user.ID, Name: "Desktop Claude", Provider: "claude-code",
	})
	if err != nil {
		t.Fatal(err)
	}
	if codex.RawKey == "" || claude.RawKey == "" || codex.RawKey == claude.RawKey {
		t.Fatalf("expected separate credentials: %#v %#v", codex, claude)
	}
	if codex.RawKey[:4] != "phk_" || claude.RawKey[:4] != "phk_" {
		t.Fatalf("unexpected key prefixes: %q %q", codex.RawKey, claude.RawKey)
	}

	identity, err := svc.AuthenticateHarnessCredential(ctx, codex.RawKey)
	if err != nil {
		t.Fatal(err)
	}
	if identity.UserID != user.ID || identity.Provider != "codex" || len(identity.Scopes) != 3 {
		t.Fatalf("unexpected harness identity: %#v", identity)
	}
	credentials, err := svc.ListHarnessCredentials(ctx, user.ID)
	if err != nil || len(credentials) != 2 {
		t.Fatalf("unexpected credentials: %#v err=%v", credentials, err)
	}
}

func TestHarnessCredentialCanBeRevokedByItsOwner(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newFeedTestService(t)
	owner, _ := svc.Register(ctx, usecase.RegisterInput{Email: "owner@example.com", Password: "correct horse"})
	other, _ := svc.Register(ctx, usecase.RegisterInput{Email: "other@example.com", Password: "correct horse"})
	created, _ := svc.CreateHarnessCredential(ctx, usecase.CreateHarnessCredentialInput{
		UserID: owner.ID, Name: "Codex", Provider: "codex",
	})

	if err := svc.RevokeHarnessCredential(ctx, other.ID, created.Credential.ID); err == nil {
		t.Fatal("another user revoked the credential")
	}
	if err := svc.RevokeHarnessCredential(ctx, owner.ID, created.Credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateHarnessCredential(ctx, created.RawKey); !errors.Is(err, usecase.ErrUnauthorized) {
		t.Fatalf("expected revoked key to be unauthorized, got %v", err)
	}
}

func TestHarnessCredentialRejectsUnsupportedProvider(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newFeedTestService(t)
	user, _ := svc.Register(ctx, usecase.RegisterInput{Email: "provider@example.com", Password: "correct horse"})
	if _, err := svc.CreateHarnessCredential(ctx, usecase.CreateHarnessCredentialInput{
		UserID: user.ID, Name: "Unknown", Provider: "something-else",
	}); err == nil {
		t.Fatal("expected unsupported provider to fail")
	}
}
