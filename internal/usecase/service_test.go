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

func TestLoginCreatesUsableSession(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)
	user, err := svc.Register(ctx, usecase.RegisterInput{Email: "login@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := svc.Login(ctx, "login@example.com", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	userID, err := svc.UserIDForSession(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if userID != user.ID {
		t.Fatalf("expected session user %s, got %s", user.ID, userID)
	}
}
