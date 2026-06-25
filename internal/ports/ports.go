package ports

import (
	"context"
	"time"

	"potpuri/internal/domain"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user domain.User) error
	FindUserByEmail(ctx context.Context, email string) (domain.User, error)
	FindUserByID(ctx context.Context, userID string) (domain.User, error)
	DeleteUser(ctx context.Context, userID string) error
	StoreTOTPSecret(ctx context.Context, userID string, secretCiphertext []byte) error
	ActivateTOTP(ctx context.Context, userID string) error
	DisableTOTP(ctx context.Context, userID string) error
	FindTOTPSecret(ctx context.Context, userID string) ([]byte, error)
}

type StoredPreauthSession struct {
	TokenHash string
	UserID    string
	ExpiresAt time.Time
}

type PreauthSessionRepository interface {
	CreatePreauthSession(ctx context.Context, session StoredPreauthSession) error
	FindPreauthSession(ctx context.Context, tokenHash string) (StoredPreauthSession, error)
	DeletePreauthSession(ctx context.Context, tokenHash string) error
}

type TOTPRecoveryRepository interface {
	StoreRecoveryCodes(ctx context.Context, userID string, codeHashes []string) error
	FindAndConsumeRecoveryCode(ctx context.Context, userID string, codeHash string) (bool, error)
	DeleteRecoveryCodes(ctx context.Context, userID string) error
}

type ItemRepository interface {
	CreateItem(ctx context.Context, item StoredItem) error
	FindItem(ctx context.Context, userID string, itemID string) (StoredItem, error)
	UpdateItem(ctx context.Context, item StoredItem) error
	ListItems(ctx context.Context, userID string) ([]StoredItem, error)
	SearchItems(ctx context.Context, userID string, tokens []string) ([]StoredItem, error)
	DeleteItem(ctx context.Context, userID string, itemID string) error
}

type BlobRepository interface {
	CreateBlob(ctx context.Context, blob StoredBlob) error
	FindBlob(ctx context.Context, userID string, blobID string) (StoredBlob, error)
	ListBlobs(ctx context.Context, userID string, itemID string) ([]StoredBlob, error)
	DeleteBlobsForItem(ctx context.Context, userID string, itemID string) error
}

type SessionRepository interface {
	CreateSession(ctx context.Context, session Session) error
	FindSession(ctx context.Context, tokenHash string) (Session, error)
	DeleteSession(ctx context.Context, tokenHash string) error
}

type APITokenRepository interface {
	CreateAPIToken(ctx context.Context, token StoredAPIToken) error
	ListAPITokens(ctx context.Context, userID string) ([]StoredAPIToken, error)
	FindAPIToken(ctx context.Context, tokenHash string) (StoredAPIToken, error)
	DeleteAPIToken(ctx context.Context, userID string, tokenID string) error
}

// BlobContentStore holds encrypted blob bytes externally (e.g. Cloudflare R2).
// When nil, the service falls back to ciphertext stored in the blob row itself.
type BlobContentStore interface {
	PutBlobContent(ctx context.Context, blobID string, ciphertext []byte) error
	GetBlobContent(ctx context.Context, blobID string) ([]byte, error)
	DeleteBlobContent(ctx context.Context, blobID string) error
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

type StoredBlob struct {
	ID          string
	UserID      string
	ItemID      string
	Filename    string
	ContentType string
	Size        int64
	Ciphertext  []byte
	CreatedAt   time.Time
}

type Session struct {
	TokenHash string
	UserID    string
	ExpiresAt time.Time
}

type StoredAPIToken struct {
	ID        string
	UserID    string
	Name      string
	TokenHash string
	CreatedAt time.Time
}

type ItemCipher interface {
	SealString(plaintext string) ([]byte, error)
	OpenString(ciphertext []byte) (string, error)
	SealBytes(plaintext []byte) ([]byte, error)
	OpenBytes(ciphertext []byte) ([]byte, error)
	SearchTokens(parts ...string) []string
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hash, password string) bool
}
