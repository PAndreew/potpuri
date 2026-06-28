package security_test

import (
	"strings"
	"testing"
	"time"

	"potpuri/internal/security"
)

func TestFeedCredentialRejectsTamperingAndExpiry(t *testing.T) {
	issuer, err := security.NewFeedCredentialIssuer("a-signing-secret-with-enough-entropy")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	token, err := issuer.IssueFeedCredential("usr_1", []string{"feed:read"}, now, now.Add(15*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	replacement := "A"
	if parts[1][0] == 'A' {
		replacement = "B"
	}
	parts[1] = replacement + parts[1][1:]
	if _, err := issuer.Verify(strings.Join(parts, "."), now); err == nil {
		t.Fatal("expected tampered credential to fail")
	}
	if _, err := issuer.Verify(token, now.Add(15*time.Minute)); err == nil {
		t.Fatal("expected expired credential to fail")
	}
}
