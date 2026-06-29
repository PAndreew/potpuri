package domain

import "time"

type HarnessProvider string

const (
	HarnessProviderCodex      HarnessProvider = "codex"
	HarnessProviderClaudeCode HarnessProvider = "claude-code"
)

type HarnessCredential struct {
	ID         string
	UserID     string
	Name       string
	Provider   HarnessProvider
	KeyHint    string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}
