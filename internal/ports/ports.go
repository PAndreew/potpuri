package ports

import (
	"context"
	"errors"
	"time"

	"potpuri/internal/domain"
)

var ErrInsufficientFeedContribution = errors.New("insufficient feed contribution")

type UserRepository interface {
	CreateUser(ctx context.Context, user domain.User) error
	FindUserByEmail(ctx context.Context, email string) (domain.User, error)
	FindUserByID(ctx context.Context, userID string) (domain.User, error)
	ListUsers(ctx context.Context) ([]domain.User, error)
	DeleteUser(ctx context.Context, userID string) error
	SetPatron(ctx context.Context, userID string, patron bool) error
	SetEmailVerified(ctx context.Context, userID string) error
	SetCaptureMode(ctx context.Context, userID string, mode string) error
	StoreTOTPSecret(ctx context.Context, userID string, secretCiphertext []byte) error
	ActivateTOTP(ctx context.Context, userID string) error
	DisableTOTP(ctx context.Context, userID string) error
	FindTOTPSecret(ctx context.Context, userID string) ([]byte, error)
}

type StoredEmailVerification struct {
	TokenHash string
	UserID    string
	ExpiresAt time.Time
}

type EmailVerificationRepository interface {
	CreateEmailVerification(ctx context.Context, v StoredEmailVerification) error
	FindEmailVerification(ctx context.Context, tokenHash string) (StoredEmailVerification, error)
	DeleteEmailVerificationsForUser(ctx context.Context, userID string) error
}

type Mailer interface {
	SendVerificationEmail(ctx context.Context, toEmail, verifyURL string) error
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
	TotalBlobSize(ctx context.Context, userID string) (int64, error)
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

type PageFetcher interface {
	FetchPage(ctx context.Context, rawURL, mode string) (string, error)
}

type StoredSecretShare struct {
	TokenHash string
	ItemID    string
	UserID    string
}

type SecretShareRepository interface {
	CreateSecretShare(ctx context.Context, share StoredSecretShare) error
	FindAndDeleteSecretShare(ctx context.Context, tokenHash string) (StoredSecretShare, error)
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

type FeedRepository interface {
	SaveFeedContribution(ctx context.Context, contribution domain.FeedContribution) error
	FindFeedContribution(ctx context.Context, userID string) (domain.FeedContribution, error)
	ListFeedContributions(ctx context.Context) ([]domain.FeedContribution, error)
	FeedTokensUsedSince(ctx context.Context, userID string, since time.Time) (int64, error)
	FeedTokensEarned(ctx context.Context, userID string) (int64, error)
	ListFeedLedger(ctx context.Context, userID string) ([]domain.FeedLedgerEntry, error)
	SettleFeedTranslation(ctx context.Context, settlement FeedSettlement, weekStart time.Time) (bool, error)
}

type FeedSettlement struct {
	JobID             string
	ContributorUserID string
	OperatorUserID    string
	Tokens            int64
	CreatedAt         time.Time
}

type FeedCredentialIssuer interface {
	IssueFeedCredential(userID string, scopes []string, issuedAt, expiresAt time.Time) (string, error)
}

type StoredHarnessCredential struct {
	domain.HarnessCredential
	TokenHash string
}

type HarnessCredentialRepository interface {
	CreateHarnessCredential(ctx context.Context, credential StoredHarnessCredential) error
	ListHarnessCredentials(ctx context.Context, userID string) ([]StoredHarnessCredential, error)
	FindHarnessCredentialByHash(ctx context.Context, tokenHash string) (StoredHarnessCredential, error)
	RevokeHarnessCredential(ctx context.Context, userID, credentialID string, revokedAt time.Time) error
	TouchHarnessCredential(ctx context.Context, credentialID string, usedAt time.Time) error
}
