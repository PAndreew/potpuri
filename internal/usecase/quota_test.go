package usecase_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"potpuri/internal/security"
	"potpuri/internal/storage/memory"
	"potpuri/internal/usecase"
)

var testQuotas = usecase.Quotas{
	FreeMaxFileSizeBytes:   100,
	FreeMaxStorageBytes:    500,
	FreeMaxAPITokens:       1,
	PatronMaxFileSizeBytes: 1000,
	PatronMaxStorageBytes:  5000,
}

func newQuotaSvc(t *testing.T) (*usecase.Service, *memory.Store) {
	t.Helper()
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{
		Users:    store,
		Items:    store,
		Sessions: store,
		Cipher:   cipher,
		Hasher:   security.NewPasswordHasher(),
		Quotas:   &testQuotas,
	})
	return svc, store
}

func TestFreeUserFileSizeLimitEnforced(t *testing.T) {
	ctx := context.Background()
	svc, _ := newQuotaSvc(t)
	user, err := svc.Register(ctx, usecase.RegisterInput{Email: "a@q.test", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateItem(ctx, usecase.CreateItemInput{
		UserID: user.ID,
		Title:  "big",
		Blobs: []usecase.BlobInput{{
			Filename:    "big.bin",
			ContentType: "application/octet-stream",
			Content:     make([]byte, 101),
		}},
	})
	if err == nil {
		t.Fatal("expected error for oversized file, got nil")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected 'limit' in error, got: %v", err)
	}
}

func TestFreeUserFileSizeAtLimitSucceeds(t *testing.T) {
	ctx := context.Background()
	svc, _ := newQuotaSvc(t)
	user, err := svc.Register(ctx, usecase.RegisterInput{Email: "b@q.test", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateItem(ctx, usecase.CreateItemInput{
		UserID: user.ID,
		Title:  "ok",
		Blobs: []usecase.BlobInput{{
			Filename:    "ok.bin",
			ContentType: "application/octet-stream",
			Content:     make([]byte, 100),
		}},
	})
	if err != nil {
		t.Fatalf("upload at limit should succeed: %v", err)
	}
}

func TestFreeUserStorageQuotaEnforced(t *testing.T) {
	ctx := context.Background()
	svc, _ := newQuotaSvc(t)
	user, err := svc.Register(ctx, usecase.RegisterInput{Email: "c@q.test", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	// Upload five 100-byte files to fill the 500-byte quota exactly.
	for i := 0; i < 5; i++ {
		_, err = svc.CreateItem(ctx, usecase.CreateItemInput{
			UserID: user.ID,
			Title:  fmt.Sprintf("item-%d", i),
			Blobs: []usecase.BlobInput{{
				Filename:    "f.bin",
				ContentType: "application/octet-stream",
				Content:     make([]byte, 100),
			}},
		})
		if err != nil {
			t.Fatalf("upload %d should succeed: %v", i, err)
		}
	}
	// One more byte pushes over the 500-byte limit.
	_, err = svc.CreateItem(ctx, usecase.CreateItemInput{
		UserID: user.ID,
		Title:  "overflow",
		Blobs: []usecase.BlobInput{{
			Filename:    "g.bin",
			ContentType: "application/octet-stream",
			Content:     make([]byte, 1),
		}},
	})
	if err == nil {
		t.Fatal("expected quota error, got nil")
	}
	if !strings.Contains(err.Error(), "quota") {
		t.Fatalf("expected 'quota' in error, got: %v", err)
	}
}

func TestFreeUserAPITokenLimitEnforced(t *testing.T) {
	ctx := context.Background()
	svc, _ := newQuotaSvc(t)
	user, err := svc.Register(ctx, usecase.RegisterInput{Email: "d@q.test", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.CreateAPIToken(ctx, usecase.CreateAPITokenInput{UserID: user.ID, Name: "first"}); err != nil {
		t.Fatalf("first token should succeed: %v", err)
	}
	_, err = svc.CreateAPIToken(ctx, usecase.CreateAPITokenInput{UserID: user.ID, Name: "second"})
	if err == nil {
		t.Fatal("expected error on second API token, got nil")
	}
	if !strings.Contains(err.Error(), "limit") && !strings.Contains(err.Error(), "token") {
		t.Fatalf("expected 'limit' or 'token' in error, got: %v", err)
	}
}

func TestPatronUserHasHigherFileSizeLimit(t *testing.T) {
	ctx := context.Background()
	svc, store := newQuotaSvc(t)
	user, err := svc.Register(ctx, usecase.RegisterInput{Email: "e@q.test", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetPatron(ctx, user.ID, true); err != nil {
		t.Fatal(err)
	}
	// 500 bytes: over free limit (100) but under patron limit (1000)
	_, err = svc.CreateItem(ctx, usecase.CreateItemInput{
		UserID: user.ID,
		Title:  "patron file",
		Blobs: []usecase.BlobInput{{
			Filename:    "big.bin",
			ContentType: "application/octet-stream",
			Content:     make([]byte, 500),
		}},
	})
	if err != nil {
		t.Fatalf("patron should upload larger files: %v", err)
	}
}

func TestPatronUserCanCreateMultipleAPITokens(t *testing.T) {
	ctx := context.Background()
	svc, store := newQuotaSvc(t)
	user, err := svc.Register(ctx, usecase.RegisterInput{Email: "f@q.test", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetPatron(ctx, user.ID, true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, err = svc.CreateAPIToken(ctx, usecase.CreateAPITokenInput{
			UserID: user.ID,
			Name:   fmt.Sprintf("tok-%d", i),
		})
		if err != nil {
			t.Fatalf("patron token %d should succeed: %v", i, err)
		}
	}
}
