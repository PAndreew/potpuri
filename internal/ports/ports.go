package ports

import (
	"context"
	"time"

	"potpuri/internal/domain"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user domain.User) error
	FindUserByEmail(ctx context.Context, email string) (domain.User, error)
}

type ItemRepository interface {
	CreateItem(ctx context.Context, item StoredItem) error
	ListItems(ctx context.Context, userID string) ([]StoredItem, error)
	SearchItems(ctx context.Context, userID string, tokens []string) ([]StoredItem, error)
	DeleteItem(ctx context.Context, userID string, itemID string) error
}

type SessionRepository interface {
	CreateSession(ctx context.Context, session Session) error
	FindSession(ctx context.Context, tokenHash string) (Session, error)
	DeleteSession(ctx context.Context, tokenHash string) error
}

type StoredItem struct {
	ID              string
	UserID          string
	Type            domain.ItemType
	TitleCiphertext []byte
	BodyCiphertext  []byte
	URLCiphertext   []byte
	SearchTokens    []string
	Tags            []string
	CreatedAt       time.Time
}

type Session struct {
	TokenHash string
	UserID    string
	ExpiresAt time.Time
}

type ItemCipher interface {
	SealString(plaintext string) ([]byte, error)
	OpenString(ciphertext []byte) (string, error)
	SearchTokens(parts ...string) []string
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hash, password string) bool
}
