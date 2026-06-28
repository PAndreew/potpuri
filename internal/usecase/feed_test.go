package usecase_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"potpuri/internal/security"
	"potpuri/internal/storage/memory"
	"potpuri/internal/usecase"
)

func newFeedTestService(t *testing.T) (*usecase.Service, *memory.Store, time.Time) {
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
		Now:      func() time.Time { return now },
	})
	return svc, store, now
}

func TestUserControlsWeeklyFeedContribution(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newFeedTestService(t)
	user, err := svc.Register(ctx, usecase.RegisterInput{Email: "contributor@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.UpdateFeedContribution(ctx, user.ID, 50_000); err != nil {
		t.Fatal(err)
	}
	status, err := svc.GetFeedContribution(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.WeeklyLimit != 50_000 || status.UsedThisWeek != 0 || status.Remaining != 50_000 {
		t.Fatalf("unexpected contribution status: %#v", status)
	}

	for _, invalid := range []int64{-1, 10_000_001} {
		if err := svc.UpdateFeedContribution(ctx, user.ID, invalid); err == nil {
			t.Fatalf("expected weekly limit %d to be rejected", invalid)
		}
	}
}

func TestAcceptedFeedTranslationSettlesExactlyOnce(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newFeedTestService(t)
	contributor, _ := svc.Register(ctx, usecase.RegisterInput{Email: "contributor@example.com", Password: "correct horse"})
	operator, _ := svc.Register(ctx, usecase.RegisterInput{Email: "operator@example.com", Password: "correct horse"})
	if err := svc.UpdateFeedContribution(ctx, contributor.ID, 10_000); err != nil {
		t.Fatal(err)
	}

	input := usecase.SettleFeedTranslationInput{
		JobID:             "job_123",
		ContributorUserID: contributor.ID,
		OperatorUserID:    operator.ID,
		Tokens:            6_840,
	}
	created, err := svc.SettleFeedTranslation(ctx, input)
	if err != nil || !created {
		t.Fatalf("first settlement failed: created=%v err=%v", created, err)
	}
	created, err = svc.SettleFeedTranslation(ctx, input)
	if err != nil || created {
		t.Fatalf("retry should be idempotent: created=%v err=%v", created, err)
	}

	contribution, _ := svc.GetFeedContribution(ctx, contributor.ID)
	if contribution.UsedThisWeek != 6_840 || contribution.Remaining != 3_160 {
		t.Fatalf("unexpected contributor status: %#v", contribution)
	}
	operatorStatus, _ := svc.GetFeedContribution(ctx, operator.ID)
	if operatorStatus.Earned != 6_840 {
		t.Fatalf("expected operator to earn 6840, got %#v", operatorStatus)
	}
	entries, err := svc.ListFeedLedger(ctx, contributor.ID)
	if err != nil || len(entries) != 1 || entries[0].Amount != -6_840 || entries[0].JobID != "job_123" {
		t.Fatalf("unexpected contributor ledger: %#v err=%v", entries, err)
	}
}

func TestFeedSettlementCannotExceedCurrentWeeklyCapacity(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newFeedTestService(t)
	contributor, _ := svc.Register(ctx, usecase.RegisterInput{Email: "small@example.com", Password: "correct horse"})
	operator, _ := svc.Register(ctx, usecase.RegisterInput{Email: "operator@example.com", Password: "correct horse"})
	_ = svc.UpdateFeedContribution(ctx, contributor.ID, 100)

	_, err := svc.SettleFeedTranslation(ctx, usecase.SettleFeedTranslationInput{
		JobID: "job_too_large", ContributorUserID: contributor.ID, OperatorUserID: operator.ID, Tokens: 101,
	})
	if !errors.Is(err, usecase.ErrInsufficientFeedContribution) {
		t.Fatalf("expected insufficient contribution error, got %v", err)
	}
	status, _ := svc.GetFeedContribution(ctx, contributor.ID)
	if status.UsedThisWeek != 0 || status.Remaining != 100 {
		t.Fatalf("failed settlement changed balance: %#v", status)
	}
}

func TestFeedServiceCanListOnlyPositiveRemainingCapacity(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newFeedTestService(t)
	active, _ := svc.Register(ctx, usecase.RegisterInput{Email: "active@example.com", Password: "correct horse"})
	inactive, _ := svc.Register(ctx, usecase.RegisterInput{Email: "inactive@example.com", Password: "correct horse"})
	_ = svc.UpdateFeedContribution(ctx, active.ID, 500)
	_ = svc.UpdateFeedContribution(ctx, inactive.ID, 0)

	capacities, err := svc.ListFeedContributionCapacity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(capacities) != 1 || capacities[0].UserID != active.ID || capacities[0].Remaining != 500 {
		t.Fatalf("unexpected capacities: %#v", capacities)
	}
}

func TestAuthenticatedUserCanRequestScopedFeedCredential(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	cipher, _ := security.NewCipher([]byte("12345678901234567890123456789012"))
	issuer, err := security.NewFeedCredentialIssuer("a-signing-secret-with-enough-entropy")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	svc := usecase.NewService(usecase.NewServiceParams{
		Users: store, Items: store, Sessions: store, Cipher: cipher,
		Hasher: security.NewPasswordHasher(), FeedCredentials: issuer, Now: func() time.Time { return now },
	})
	user, _ := svc.Register(ctx, usecase.RegisterInput{Email: "feed-auth@example.com", Password: "correct horse"})

	credential, err := svc.IssueFeedCredential(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Token == "" || !credential.ExpiresAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("unexpected credential: %#v", credential)
	}
	claims, err := issuer.Verify(credential.Token, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != user.ID || len(claims.Scopes) != 3 {
		t.Fatalf("unexpected claims: %#v", claims)
	}
}

func TestUserCanSaveFeedTranslationAsEncryptedPotpuriItem(t *testing.T) {
	ctx := context.Background()
	svc, store, _ := newFeedTestService(t)
	user, _ := svc.Register(ctx, usecase.RegisterInput{Email: "reader@example.com", Password: "correct horse"})
	item, err := svc.SaveFeedTranslation(ctx, usecase.SaveFeedTranslationInput{
		UserID: user.ID, Title: "Translated article", Markdown: "# Bonjour\n\nLe contenu.",
		OriginalURL: "https://example.cn/articles/1", Language: "fr",
	})
	if err != nil {
		t.Fatal(err)
	}
	if item.SourceURL != "https://example.cn/articles/1" || item.Body != "# Bonjour\n\nLe contenu." {
		t.Fatalf("unexpected saved item: %#v", item)
	}
	if len(item.Tags) != 3 || item.Tags[0] != "feed" || item.Tags[2] != "language-fr" {
		t.Fatalf("unexpected feed tags: %#v", item.Tags)
	}
	stored, _ := store.FindItem(ctx, user.ID, item.ID)
	if strings.Contains(string(stored.BodyCiphertext), "Bonjour") {
		t.Fatal("saved translation was not encrypted")
	}
}
