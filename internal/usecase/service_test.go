package usecase_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"potpuri/internal/domain"
	"potpuri/internal/security"
	"potpuri/internal/storage/memory"
	"potpuri/internal/usecase"
)

func newTestService(t *testing.T) (*usecase.Service, *memory.Store) {
	t.Helper()
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	svc := usecase.NewService(usecase.NewServiceParams{
		Users:    store,
		Items:    store,
		Sessions: store,
		Cipher:   cipher,
		Hasher:   security.NewPasswordHasher(),
		Now: func() time.Time {
			now = now.Add(time.Minute)
			return now
		},
	})
	return svc, store
}

func TestUserCanRegisterAddEncryptedNoteAndListNewestFirst(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)

	user, err := svc.Register(ctx, usecase.RegisterInput{Email: "A@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateItem(ctx, usecase.CreateItemInput{
		UserID: user.ID,
		Type:   domain.ItemTypeNote,
		Title:  "First",
		Body:   "older note",
		Tags:   []string{"Inbox"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateItem(ctx, usecase.CreateItemInput{
		UserID: user.ID,
		Type:   domain.ItemTypeNote,
		Title:  "Second",
		Body:   "newer note",
		Tags:   []string{"Inbox", "personal notes"},
	})
	if err != nil {
		t.Fatal(err)
	}

	items, err := svc.ListItems(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].Title != "Second" || items[1].Title != "First" {
		t.Fatalf("items were not newest first: %#v", items)
	}
	if got := strings.Join(items[0].Tags, ","); got != "inbox,personal-notes" {
		t.Fatalf("tags were not normalized: %s", got)
	}

	stored, err := store.ListItems(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored[0].BodyCiphertext), "newer note") {
		t.Fatal("stored ciphertext leaked plaintext body")
	}
}

func TestSearchFindsEncryptedItemsByBlindIndex(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)
	user, err := svc.Register(ctx, usecase.RegisterInput{Email: "search@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = svc.CreateItem(ctx, usecase.CreateItemInput{UserID: user.ID, Title: "Recipe", Body: "sourdough starter notes"})
	_, _ = svc.CreateItem(ctx, usecase.CreateItemInput{UserID: user.ID, Title: "Link", Body: "postgres backup article"})

	items, err := svc.SearchItems(ctx, user.ID, "starter")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Title != "Recipe" {
		t.Fatalf("expected recipe search result, got %#v", items)
	}
}

func TestUserCanDeleteOnlyTheirOwnItem(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)
	owner, err := svc.Register(ctx, usecase.RegisterInput{Email: "owner@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := svc.Register(ctx, usecase.RegisterInput{Email: "other@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	item, err := svc.CreateItem(ctx, usecase.CreateItemInput{UserID: owner.ID, Title: "Delete me", Body: "private"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteItem(ctx, other.ID, item.ID); err == nil {
		t.Fatal("expected other user delete to fail")
	}
	items, err := svc.ListItems(ctx, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("item should still exist for owner: %#v", items)
	}
	if err := svc.DeleteItem(ctx, owner.ID, item.ID); err != nil {
		t.Fatal(err)
	}
	items, err = svc.ListItems(ctx, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("expected deleted item to be gone, got %#v", items)
	}
}

func TestChangePassword(t *testing.T) {
	ctx := context.Background()

	t.Run("succeeds with correct current password", func(t *testing.T) {
		svc, _ := newTestService(t)
		user, err := svc.Register(ctx, usecase.RegisterInput{Email: "chpw@example.com", Password: "oldpassword"})
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.ChangePassword(ctx, usecase.ChangePasswordInput{
			UserID:          user.ID,
			CurrentPassword: "oldpassword",
			NewPassword:     "newpassword123",
		}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := svc.Login(ctx, user.Email, "newpassword123"); err != nil {
			t.Fatal("login with new password failed:", err)
		}
	})

	t.Run("rejects wrong current password", func(t *testing.T) {
		svc, _ := newTestService(t)
		user, err := svc.Register(ctx, usecase.RegisterInput{Email: "chpw2@example.com", Password: "oldpassword"})
		if err != nil {
			t.Fatal(err)
		}
		err = svc.ChangePassword(ctx, usecase.ChangePasswordInput{
			UserID:          user.ID,
			CurrentPassword: "wrongpassword",
			NewPassword:     "newpassword123",
		})
		if err == nil {
			t.Fatal("expected error for wrong current password")
		}
	})

	t.Run("rejects new password shorter than 8 chars", func(t *testing.T) {
		svc, _ := newTestService(t)
		user, err := svc.Register(ctx, usecase.RegisterInput{Email: "chpw3@example.com", Password: "oldpassword"})
		if err != nil {
			t.Fatal(err)
		}
		err = svc.ChangePassword(ctx, usecase.ChangePasswordInput{
			UserID:          user.ID,
			CurrentPassword: "oldpassword",
			NewPassword:     "short",
		})
		if err == nil {
			t.Fatal("expected error for too-short new password")
		}
	})

	t.Run("rejects empty userID", func(t *testing.T) {
		svc, _ := newTestService(t)
		err := svc.ChangePassword(ctx, usecase.ChangePasswordInput{
			UserID:          "",
			CurrentPassword: "oldpassword",
			NewPassword:     "newpassword123",
		})
		if err == nil {
			t.Fatal("expected unauthorized error")
		}
	})
}

func TestLoginCreatesUsableSession(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)
	user, err := svc.Register(ctx, usecase.RegisterInput{Email: "login@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	loginResult, err := svc.Login(ctx, "login@example.com", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	userID, err := svc.UserIDForSession(ctx, loginResult.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if userID != user.ID {
		t.Fatalf("expected session user %s, got %s", user.ID, userID)
	}
}
