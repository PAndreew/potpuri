package usecase

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"

	"potpuri/internal/domain"
	"potpuri/internal/ports"
)

var (
	ErrInvalidCredentials           = errors.New("invalid credentials")
	ErrUnauthorized                 = errors.New("unauthorized")
	ErrNotFound                     = errors.New("not found")
	ErrInsufficientFeedContribution = ports.ErrInsufficientFeedContribution
)

// Quotas defines per-tier upload and API token limits.
type Quotas struct {
	FreeMaxFileSizeBytes   int64
	FreeMaxStorageBytes    int64
	FreeMaxAPITokens       int
	PatronMaxFileSizeBytes int64
	PatronMaxStorageBytes  int64
}

// DefaultQuotas are the live production limits.
var DefaultQuotas = Quotas{
	FreeMaxFileSizeBytes:   25 * 1024 * 1024,
	FreeMaxStorageBytes:    250 * 1024 * 1024,
	FreeMaxAPITokens:       1,
	PatronMaxFileSizeBytes: 100 * 1024 * 1024,
	PatronMaxStorageBytes:  5 * 1024 * 1024 * 1024,
}

type quota struct {
	maxFileSizeBytes int64 // 0 = unlimited
	maxStorageBytes  int64 // 0 = unlimited
	maxAPITokens     int   // 0 = unlimited
}

func (q Quotas) forUser(patron bool) quota {
	if patron {
		return quota{q.PatronMaxFileSizeBytes, q.PatronMaxStorageBytes, 0}
	}
	return quota{q.FreeMaxFileSizeBytes, q.FreeMaxStorageBytes, q.FreeMaxAPITokens}
}

func formatBytes(b int64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.0f GB", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.0f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.0f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

type Service struct {
	users              ports.UserRepository
	items              ports.ItemRepository
	blobs              ports.BlobRepository
	blobContent        ports.BlobContentStore
	sessions           ports.SessionRepository
	apiTokens          ports.APITokenRepository
	preauthSessions    ports.PreauthSessionRepository
	recoveries         ports.TOTPRecoveryRepository
	emailVerifications ports.EmailVerificationRepository
	secretShares       ports.SecretShareRepository
	feed               ports.FeedRepository
	feedCredentials    ports.FeedCredentialIssuer
	harnessCredentials ports.HarnessCredentialRepository
	fetcher            ports.PageFetcher
	mailer             ports.Mailer
	cipher             ports.ItemCipher
	hasher             ports.PasswordHasher
	now                func() time.Time
	quotas             Quotas
	publicURL          string
}

type NewServiceParams struct {
	Users              ports.UserRepository
	Items              ports.ItemRepository
	Blobs              ports.BlobRepository
	BlobContent        ports.BlobContentStore
	Sessions           ports.SessionRepository
	APITokens          ports.APITokenRepository
	PreauthSessions    ports.PreauthSessionRepository
	Recoveries         ports.TOTPRecoveryRepository
	EmailVerifications ports.EmailVerificationRepository
	SecretShares       ports.SecretShareRepository
	Feed               ports.FeedRepository
	FeedCredentials    ports.FeedCredentialIssuer
	HarnessCredentials ports.HarnessCredentialRepository
	Fetcher            ports.PageFetcher
	Mailer             ports.Mailer
	Cipher             ports.ItemCipher
	Hasher             ports.PasswordHasher
	Now                func() time.Time
	Quotas             *Quotas // nil means DefaultQuotas
	PublicURL          string
}

func NewService(params NewServiceParams) *Service {
	now := params.Now
	if now == nil {
		now = time.Now
	}
	blobs := params.Blobs
	if blobs == nil {
		if repo, ok := params.Items.(ports.BlobRepository); ok {
			blobs = repo
		}
	}
	apiTokens := params.APITokens
	if apiTokens == nil {
		if repo, ok := params.Sessions.(ports.APITokenRepository); ok {
			apiTokens = repo
		}
	}
	preauthSessions := params.PreauthSessions
	if preauthSessions == nil {
		if repo, ok := params.Sessions.(ports.PreauthSessionRepository); ok {
			preauthSessions = repo
		}
	}
	recoveries := params.Recoveries
	if recoveries == nil {
		if repo, ok := params.Sessions.(ports.TOTPRecoveryRepository); ok {
			recoveries = repo
		}
	}
	quotas := DefaultQuotas
	if params.Quotas != nil {
		quotas = *params.Quotas
	}
	emailVerifications := params.EmailVerifications
	if emailVerifications == nil {
		if repo, ok := params.Sessions.(ports.EmailVerificationRepository); ok {
			emailVerifications = repo
		}
	}
	feed := params.Feed
	if feed == nil {
		if repo, ok := params.Users.(ports.FeedRepository); ok {
			feed = repo
		}
	}
	harnessCredentials := params.HarnessCredentials
	if harnessCredentials == nil {
		if repo, ok := params.Users.(ports.HarnessCredentialRepository); ok {
			harnessCredentials = repo
		}
	}
	return &Service{
		users:              params.Users,
		items:              params.Items,
		blobs:              blobs,
		blobContent:        params.BlobContent,
		sessions:           params.Sessions,
		apiTokens:          apiTokens,
		preauthSessions:    preauthSessions,
		recoveries:         recoveries,
		emailVerifications: emailVerifications,
		secretShares:       params.SecretShares,
		feed:               feed,
		feedCredentials:    params.FeedCredentials,
		harnessCredentials: harnessCredentials,
		fetcher:            params.Fetcher,
		mailer:             params.Mailer,
		cipher:             params.Cipher,
		hasher:             params.Hasher,
		now:                now,
		quotas:             quotas,
		publicURL:          params.PublicURL,
	}
}

type RegisterInput struct {
	Email    string
	Password string
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (domain.User, error) {
	email := strings.TrimSpace(strings.ToLower(input.Email))
	if email == "" || len(input.Password) < 8 {
		return domain.User{}, fmt.Errorf("email and password of at least 8 chars are required")
	}
	hash, err := s.hasher.Hash(input.Password)
	if err != nil {
		return domain.User{}, err
	}
	user := domain.User{
		ID:           newID("usr"),
		Email:        email,
		PasswordHash: hash,
		CreatedAt:    s.now().UTC(),
	}
	if err := s.users.CreateUser(ctx, user); err != nil {
		return domain.User{}, err
	}
	_ = s.sendVerificationEmail(ctx, user) // best-effort; don't fail registration if email fails
	return user, nil
}

func (s *Service) sendVerificationEmail(ctx context.Context, user domain.User) error {
	if s.mailer == nil || s.emailVerifications == nil {
		return nil
	}
	_ = s.emailVerifications.DeleteEmailVerificationsForUser(ctx, user.ID)
	token := randomToken()
	if err := s.emailVerifications.CreateEmailVerification(ctx, ports.StoredEmailVerification{
		TokenHash: hashToken(token),
		UserID:    user.ID,
		ExpiresAt: s.now().UTC().Add(48 * time.Hour),
	}); err != nil {
		return err
	}
	return s.mailer.SendVerificationEmail(ctx, user.Email, s.publicURL+"/verify-email?token="+token)
}

func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	if s.emailVerifications == nil {
		return fmt.Errorf("email verification not configured")
	}
	v, err := s.emailVerifications.FindEmailVerification(ctx, hashToken(token))
	if err != nil {
		return fmt.Errorf("invalid or expired verification link")
	}
	if !v.ExpiresAt.After(s.now().UTC()) {
		_ = s.emailVerifications.DeleteEmailVerificationsForUser(ctx, v.UserID)
		return fmt.Errorf("verification link has expired")
	}
	if err := s.users.SetEmailVerified(ctx, v.UserID); err != nil {
		return err
	}
	return s.emailVerifications.DeleteEmailVerificationsForUser(ctx, v.UserID)
}

func (s *Service) ResendVerification(ctx context.Context, userID string) error {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if user.EmailVerified {
		return nil
	}
	return s.sendVerificationEmail(ctx, user)
}

type LoginResult struct {
	SessionToken string
	PreauthToken string
	RequiresTOTP bool
}

func (s *Service) Login(ctx context.Context, email, password string) (LoginResult, error) {
	user, err := s.users.FindUserByEmail(ctx, strings.TrimSpace(strings.ToLower(email)))
	if err != nil || !s.hasher.Verify(user.PasswordHash, password) {
		return LoginResult{}, ErrInvalidCredentials
	}
	if user.TOTPEnabled && s.preauthSessions != nil {
		raw := randomToken()
		preauth := ports.StoredPreauthSession{
			TokenHash: hashToken(raw),
			UserID:    user.ID,
			ExpiresAt: s.now().UTC().Add(5 * time.Minute),
		}
		if err := s.preauthSessions.CreatePreauthSession(ctx, preauth); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{PreauthToken: raw, RequiresTOTP: true}, nil
	}
	token := randomToken()
	session := ports.Session{
		TokenHash: hashToken(token),
		UserID:    user.ID,
		ExpiresAt: s.now().UTC().Add(30 * 24 * time.Hour),
	}
	if err := s.sessions.CreateSession(ctx, session); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{SessionToken: token}, nil
}

var recoveryCodeRE = regexp.MustCompile(`^[A-Z2-9]{4}-[A-Z2-9]{4}$`)

func (s *Service) SetupTOTP(ctx context.Context, userID string) (otpauthURI, secret string, err error) {
	if userID == "" {
		return "", "", ErrUnauthorized
	}
	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil {
		return "", "", ErrUnauthorized
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Potpuri", AccountName: user.Email})
	if err != nil {
		return "", "", err
	}
	ciphertext, err := s.cipher.SealBytes([]byte(key.Secret()))
	if err != nil {
		return "", "", err
	}
	if err := s.users.StoreTOTPSecret(ctx, userID, ciphertext); err != nil {
		return "", "", err
	}
	return key.URL(), key.Secret(), nil
}

func (s *Service) ConfirmTOTP(ctx context.Context, userID, secret, code string) ([]string, error) {
	if userID == "" {
		return nil, ErrUnauthorized
	}
	if !totp.Validate(code, secret) {
		return nil, fmt.Errorf("invalid code")
	}
	if err := s.users.ActivateTOTP(ctx, userID); err != nil {
		return nil, err
	}
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		plain := newRecoveryCode()
		codes[i] = plain
		hashes[i] = hashToken(plain)
	}
	if err := s.recoveries.StoreRecoveryCodes(ctx, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

func (s *Service) DisableTOTP(ctx context.Context, userID, code string) error {
	if userID == "" {
		return ErrUnauthorized
	}
	ciphertext, err := s.users.FindTOTPSecret(ctx, userID)
	if err != nil {
		return fmt.Errorf("2FA not set up")
	}
	secretBytes, err := s.cipher.OpenBytes(ciphertext)
	if err != nil {
		return err
	}
	if !totp.Validate(code, string(secretBytes)) {
		return fmt.Errorf("invalid code")
	}
	if err := s.users.DisableTOTP(ctx, userID); err != nil {
		return err
	}
	return s.recoveries.DeleteRecoveryCodes(ctx, userID)
}

func (s *Service) UserIDForPreauthToken(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", ErrUnauthorized
	}
	preauth, err := s.preauthSessions.FindPreauthSession(ctx, hashToken(token))
	if err != nil || !preauth.ExpiresAt.After(s.now().UTC()) {
		return "", ErrUnauthorized
	}
	return preauth.UserID, nil
}

func (s *Service) CompleteLoginTOTP(ctx context.Context, preauthToken, code string) (string, error) {
	userID, err := s.UserIDForPreauthToken(ctx, preauthToken)
	if err != nil {
		return "", ErrUnauthorized
	}
	ciphertext, err := s.users.FindTOTPSecret(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("2FA not configured")
	}
	secretBytes, err := s.cipher.OpenBytes(ciphertext)
	if err != nil {
		return "", err
	}
	var valid bool
	if recoveryCodeRE.MatchString(strings.ToUpper(strings.TrimSpace(code))) {
		codeHash := hashToken(strings.ToUpper(strings.TrimSpace(code)))
		valid, err = s.recoveries.FindAndConsumeRecoveryCode(ctx, userID, codeHash)
		if err != nil {
			return "", err
		}
	} else {
		valid = totp.Validate(strings.TrimSpace(code), string(secretBytes))
	}
	if !valid {
		return "", fmt.Errorf("invalid code")
	}
	_ = s.preauthSessions.DeletePreauthSession(ctx, hashToken(preauthToken))
	token := randomToken()
	session := ports.Session{
		TokenHash: hashToken(token),
		UserID:    userID,
		ExpiresAt: s.now().UTC().Add(30 * 24 * time.Hour),
	}
	if err := s.sessions.CreateSession(ctx, session); err != nil {
		return "", err
	}
	return token, nil
}

func newRecoveryCode() string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	result := make([]byte, 9)
	for i := 0; i < 4; i++ {
		result[i] = chars[int(b[i])%len(chars)]
	}
	result[4] = '-'
	for i := 0; i < 4; i++ {
		result[5+i] = chars[int(b[4+i])%len(chars)]
	}
	return string(result)
}

func (s *Service) GetUser(ctx context.Context, userID string) (domain.User, error) {
	if userID == "" {
		return domain.User{}, ErrUnauthorized
	}
	return s.users.FindUserByID(ctx, userID)
}

func (s *Service) SetPatron(ctx context.Context, userID string, patron bool) error {
	if strings.TrimSpace(userID) == "" {
		return ErrUnauthorized
	}
	return s.users.SetPatron(ctx, strings.TrimSpace(userID), patron)
}

func (s *Service) ListUsers(ctx context.Context) ([]domain.User, error) {
	return s.users.ListUsers(ctx)
}

func (s *Service) DeleteAccount(ctx context.Context, userID, password string) error {
	if userID == "" {
		return ErrUnauthorized
	}
	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil {
		return ErrUnauthorized
	}
	if !s.hasher.Verify(user.PasswordHash, password) {
		return fmt.Errorf("incorrect password")
	}
	return s.users.DeleteUser(ctx, userID)
}

func (s *Service) UserIDForSession(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", ErrUnauthorized
	}
	session, err := s.sessions.FindSession(ctx, hashToken(token))
	if err != nil || !session.ExpiresAt.After(s.now().UTC()) {
		return "", ErrUnauthorized
	}
	return session.UserID, nil
}

type APIToken struct {
	ID        string
	UserID    string
	Name      string
	CreatedAt time.Time
}

type CreateAPITokenInput struct {
	UserID string
	Name   string
}

type CreateAPITokenResult struct {
	Token    APIToken
	RawToken string
}

func (s *Service) CreateAPIToken(ctx context.Context, input CreateAPITokenInput) (CreateAPITokenResult, error) {
	if input.UserID == "" {
		return CreateAPITokenResult{}, ErrUnauthorized
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return CreateAPITokenResult{}, fmt.Errorf("token name is required")
	}
	if len(name) > 80 {
		name = name[:80]
	}
	user, err := s.users.FindUserByID(ctx, input.UserID)
	if err != nil {
		return CreateAPITokenResult{}, ErrUnauthorized
	}
	q := s.quotas.forUser(user.Patron)
	if q.maxAPITokens > 0 {
		existing, err := s.apiTokens.ListAPITokens(ctx, input.UserID)
		if err != nil {
			return CreateAPITokenResult{}, err
		}
		if len(existing) >= q.maxAPITokens {
			return CreateAPITokenResult{}, fmt.Errorf("your account is limited to %d API token(s); upgrade to Patron for unlimited keys", q.maxAPITokens)
		}
	}
	raw := "ptk_" + randomToken()
	stored := ports.StoredAPIToken{
		ID:        newID("tok"),
		UserID:    input.UserID,
		Name:      name,
		TokenHash: hashToken(raw),
		CreatedAt: s.now().UTC(),
	}
	if err := s.apiTokens.CreateAPIToken(ctx, stored); err != nil {
		return CreateAPITokenResult{}, err
	}
	return CreateAPITokenResult{
		Token:    APIToken{ID: stored.ID, UserID: stored.UserID, Name: stored.Name, CreatedAt: stored.CreatedAt},
		RawToken: raw,
	}, nil
}

func (s *Service) ListAPITokens(ctx context.Context, userID string) ([]APIToken, error) {
	if userID == "" {
		return nil, ErrUnauthorized
	}
	stored, err := s.apiTokens.ListAPITokens(ctx, userID)
	if err != nil {
		return nil, err
	}
	tokens := make([]APIToken, len(stored))
	for i, t := range stored {
		tokens[i] = APIToken{ID: t.ID, UserID: t.UserID, Name: t.Name, CreatedAt: t.CreatedAt}
	}
	return tokens, nil
}

func (s *Service) RevokeAPIToken(ctx context.Context, userID, tokenID string) error {
	if userID == "" {
		return ErrUnauthorized
	}
	return s.apiTokens.DeleteAPIToken(ctx, userID, strings.TrimSpace(tokenID))
}

func (s *Service) UserIDForAPIToken(ctx context.Context, rawToken string) (string, error) {
	if rawToken == "" {
		return "", ErrUnauthorized
	}
	t, err := s.apiTokens.FindAPIToken(ctx, hashToken(rawToken))
	if err != nil {
		return "", ErrUnauthorized
	}
	return t.UserID, nil
}

type CreateItemInput struct {
	UserID    string
	Type      domain.ItemType
	Title     string
	Body      string
	SourceURL string
	Tags      []string
	Blobs     []BlobInput
}

type BlobInput struct {
	Filename    string
	ContentType string
	Content     []byte
}

func (s *Service) UpdateCaptureMode(ctx context.Context, userID, mode string) error {
	if userID == "" {
		return ErrUnauthorized
	}
	switch mode {
	case "url", "meta", "full":
	default:
		return fmt.Errorf("invalid capture mode")
	}
	return s.users.SetCaptureMode(ctx, userID, mode)
}

func (s *Service) CreateItem(ctx context.Context, input CreateItemInput) (domain.Item, error) {
	if input.UserID == "" {
		return domain.Item{}, ErrUnauthorized
	}
	if err := s.validateBlobQuota(ctx, input.UserID, input.Blobs); err != nil {
		return domain.Item{}, err
	}
	if input.Type == "" {
		input.Type = domain.ItemTypeNote
	}
	// Auto-fetch page content when URL is present, body is empty, and user has a non-default capture mode.
	if input.SourceURL != "" && strings.TrimSpace(input.Body) == "" && s.fetcher != nil {
		if user, err := s.users.FindUserByID(ctx, input.UserID); err == nil {
			mode := user.CaptureMode
			if mode == "" {
				mode = "url"
			}
			if mode != "url" {
				if body, err := s.fetcher.FetchPage(ctx, input.SourceURL, mode); err == nil {
					input.Body = body
				}
			}
		}
	}
	title, err := s.cipher.SealString(strings.TrimSpace(input.Title))
	if err != nil {
		return domain.Item{}, err
	}
	body, err := s.cipher.SealString(input.Body)
	if err != nil {
		return domain.Item{}, err
	}
	sourceURL, err := s.cipher.SealString(strings.TrimSpace(input.SourceURL))
	if err != nil {
		return domain.Item{}, err
	}
	item := domain.Item{
		ID:        newID("itm"),
		UserID:    input.UserID,
		Type:      input.Type,
		Title:     strings.TrimSpace(input.Title),
		Body:      input.Body,
		SourceURL: strings.TrimSpace(input.SourceURL),
		Tags:      domain.NormalizeTags(input.Tags),
		CreatedAt: s.now().UTC(),
	}
	stored := ports.StoredItem{
		ID:              item.ID,
		UserID:          item.UserID,
		Type:            item.Type,
		TitleCiphertext: title,
		BodyCiphertext:  body,
		URLCiphertext:   sourceURL,
		SearchTokens:    s.cipher.SearchTokens(item.Title, item.Body, item.SourceURL, strings.Join(item.Tags, " "), blobSearchText(input.Blobs)),
		Tags:            item.Tags,
		CreatedAt:       item.CreatedAt,
	}
	if err := s.items.CreateItem(ctx, stored); err != nil {
		return domain.Item{}, err
	}
	if err := s.createBlobs(ctx, item, input.Blobs); err != nil {
		return domain.Item{}, err
	}
	return s.GetItem(ctx, item.UserID, item.ID)
}

type UpdateItemInput struct {
	ID        string
	UserID    string
	Type      domain.ItemType
	Title     string
	Body      string
	SourceURL string
	Tags      []string
	Blobs     []BlobInput
}

func (s *Service) GetItem(ctx context.Context, userID, itemID string) (domain.Item, error) {
	if userID == "" {
		return domain.Item{}, ErrUnauthorized
	}
	itemID = strings.TrimSpace(itemID)
	if itemID == "" {
		return domain.Item{}, ErrNotFound
	}
	stored, err := s.items.FindItem(ctx, userID, itemID)
	if err != nil {
		return domain.Item{}, err
	}
	items, err := s.decryptItems(ctx, []ports.StoredItem{stored})
	if err != nil {
		return domain.Item{}, err
	}
	return items[0], nil
}

func (s *Service) UpdateItem(ctx context.Context, input UpdateItemInput) (domain.Item, error) {
	if input.UserID == "" {
		return domain.Item{}, ErrUnauthorized
	}
	if err := s.validateBlobQuota(ctx, input.UserID, input.Blobs); err != nil {
		return domain.Item{}, err
	}
	input.ID = strings.TrimSpace(input.ID)
	if input.ID == "" {
		return domain.Item{}, ErrNotFound
	}
	existing, err := s.items.FindItem(ctx, input.UserID, input.ID)
	if err != nil {
		return domain.Item{}, err
	}
	existingBlobSearchText := ""
	if s.blobs != nil {
		blobs, err := s.blobs.ListBlobs(ctx, input.UserID, input.ID)
		if err != nil {
			return domain.Item{}, err
		}
		existingBlobSearchText = storedBlobSearchText(blobs)
	}
	if input.Type == "" {
		input.Type = domain.ItemTypeNote
	}
	title, err := s.cipher.SealString(strings.TrimSpace(input.Title))
	if err != nil {
		return domain.Item{}, err
	}
	body, err := s.cipher.SealString(input.Body)
	if err != nil {
		return domain.Item{}, err
	}
	sourceURL, err := s.cipher.SealString(strings.TrimSpace(input.SourceURL))
	if err != nil {
		return domain.Item{}, err
	}
	item := domain.Item{
		ID:        input.ID,
		UserID:    input.UserID,
		Type:      input.Type,
		Title:     strings.TrimSpace(input.Title),
		Body:      input.Body,
		SourceURL: strings.TrimSpace(input.SourceURL),
		Tags:      domain.NormalizeTags(input.Tags),
		CreatedAt: existing.CreatedAt,
	}
	stored := ports.StoredItem{
		ID:              item.ID,
		UserID:          item.UserID,
		Type:            item.Type,
		TitleCiphertext: title,
		BodyCiphertext:  body,
		URLCiphertext:   sourceURL,
		SearchTokens:    s.cipher.SearchTokens(item.Title, item.Body, item.SourceURL, strings.Join(item.Tags, " "), existingBlobSearchText, blobSearchText(input.Blobs)),
		Tags:            item.Tags,
		CreatedAt:       item.CreatedAt,
	}
	if err := s.items.UpdateItem(ctx, stored); err != nil {
		return domain.Item{}, err
	}
	if err := s.createBlobs(ctx, item, input.Blobs); err != nil {
		return domain.Item{}, err
	}
	return s.GetItem(ctx, item.UserID, item.ID)
}

func (s *Service) GetBlob(ctx context.Context, userID, blobID string) (domain.Blob, []byte, error) {
	if userID == "" {
		return domain.Blob{}, nil, ErrUnauthorized
	}
	stored, err := s.blobs.FindBlob(ctx, userID, strings.TrimSpace(blobID))
	if err != nil {
		return domain.Blob{}, nil, err
	}
	ciphertext := stored.Ciphertext
	if len(ciphertext) == 0 && s.blobContent != nil {
		ciphertext, err = s.blobContent.GetBlobContent(ctx, stored.ID)
		if err != nil {
			return domain.Blob{}, nil, err
		}
	}
	content, err := s.cipher.OpenBytes(ciphertext)
	if err != nil {
		return domain.Blob{}, nil, err
	}
	return domain.Blob{
		ID:          stored.ID,
		UserID:      stored.UserID,
		ItemID:      stored.ItemID,
		Filename:    stored.Filename,
		ContentType: stored.ContentType,
		Size:        stored.Size,
		CreatedAt:   stored.CreatedAt,
	}, content, nil
}

func (s *Service) validateBlobQuota(ctx context.Context, userID string, inputs []BlobInput) error {
	if s.blobs == nil || len(inputs) == 0 {
		return nil
	}
	var active []BlobInput
	for _, in := range inputs {
		if len(in.Content) > 0 {
			active = append(active, in)
		}
	}
	if len(active) == 0 {
		return nil
	}
	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil {
		return err
	}
	q := s.quotas.forUser(user.Patron)
	if q.maxFileSizeBytes > 0 {
		for _, in := range active {
			if int64(len(in.Content)) > q.maxFileSizeBytes {
				return fmt.Errorf("%s is %s, exceeding the %s per-file limit for your account",
					in.Filename, formatBytes(int64(len(in.Content))), formatBytes(q.maxFileSizeBytes))
			}
		}
	}
	if q.maxStorageBytes > 0 {
		used, err := s.blobs.TotalBlobSize(ctx, userID)
		if err != nil {
			return err
		}
		var incoming int64
		for _, in := range active {
			incoming += int64(len(in.Content))
		}
		if used+incoming > q.maxStorageBytes {
			return fmt.Errorf("this upload would exceed your storage quota of %s", formatBytes(q.maxStorageBytes))
		}
	}
	return nil
}

func (s *Service) createBlobs(ctx context.Context, item domain.Item, inputs []BlobInput) error {
	if s.blobs == nil {
		return nil
	}
	for _, input := range inputs {
		if len(input.Content) == 0 {
			continue
		}
		ciphertext, err := s.cipher.SealBytes(input.Content)
		if err != nil {
			return err
		}
		contentType := strings.TrimSpace(input.ContentType)
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		blobID := newID("blb")
		stored := ports.StoredBlob{
			ID:          blobID,
			UserID:      item.UserID,
			ItemID:      item.ID,
			Filename:    strings.TrimSpace(input.Filename),
			ContentType: contentType,
			Size:        int64(len(input.Content)),
			CreatedAt:   item.CreatedAt,
		}
		if s.blobContent != nil {
			if err := s.blobContent.PutBlobContent(ctx, blobID, ciphertext); err != nil {
				return err
			}
		} else {
			stored.Ciphertext = ciphertext
		}
		if err := s.blobs.CreateBlob(ctx, stored); err != nil {
			return err
		}
	}
	return nil
}

func blobSearchText(blobs []BlobInput) string {
	var parts []string
	for _, blob := range blobs {
		parts = append(parts, blob.Filename, blob.ContentType)
	}
	return strings.Join(parts, " ")
}

func storedBlobSearchText(blobs []ports.StoredBlob) string {
	var parts []string
	for _, blob := range blobs {
		parts = append(parts, blob.Filename, blob.ContentType)
	}
	return strings.Join(parts, " ")
}

func (s *Service) ListItems(ctx context.Context, userID string) ([]domain.Item, error) {
	if userID == "" {
		return nil, ErrUnauthorized
	}
	stored, err := s.items.ListItems(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.decryptItems(ctx, stored)
}

func (s *Service) SearchItems(ctx context.Context, userID, query string) ([]domain.Item, error) {
	if userID == "" {
		return nil, ErrUnauthorized
	}
	tokens := s.cipher.SearchTokens(query)
	if len(tokens) == 0 {
		return s.ListItems(ctx, userID)
	}
	stored, err := s.items.SearchItems(ctx, userID, tokens)
	if err != nil {
		return nil, err
	}
	return s.decryptItems(ctx, stored)
}

func (s *Service) DeleteItem(ctx context.Context, userID, itemID string) error {
	if userID == "" {
		return ErrUnauthorized
	}
	itemID = strings.TrimSpace(itemID)
	if itemID == "" {
		return ErrNotFound
	}
	return s.items.DeleteItem(ctx, userID, itemID)
}

func (s *Service) decryptItems(ctx context.Context, stored []ports.StoredItem) ([]domain.Item, error) {
	items := make([]domain.Item, 0, len(stored))
	for _, storedItem := range stored {
		title, err := s.cipher.OpenString(storedItem.TitleCiphertext)
		if err != nil {
			return nil, err
		}
		body, err := s.cipher.OpenString(storedItem.BodyCiphertext)
		if err != nil {
			return nil, err
		}
		sourceURL, err := s.cipher.OpenString(storedItem.URLCiphertext)
		if err != nil {
			return nil, err
		}
		item := domain.Item{
			ID:        storedItem.ID,
			UserID:    storedItem.UserID,
			Type:      storedItem.Type,
			Title:     title,
			Body:      body,
			SourceURL: sourceURL,
			Tags:      storedItem.Tags,
			CreatedAt: storedItem.CreatedAt,
		}
		if s.blobs != nil {
			blobs, err := s.blobs.ListBlobs(ctx, storedItem.UserID, storedItem.ID)
			if err != nil {
				return nil, err
			}
			for _, blob := range blobs {
				item.Blobs = append(item.Blobs, domain.Blob{
					ID:          blob.ID,
					UserID:      blob.UserID,
					ItemID:      blob.ItemID,
					Filename:    blob.Filename,
					ContentType: blob.ContentType,
					Size:        blob.Size,
					CreatedAt:   blob.CreatedAt,
				})
			}
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *Service) CreateSecretShare(ctx context.Context, userID, itemID string) (string, error) {
	if userID == "" {
		return "", ErrUnauthorized
	}
	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil {
		return "", ErrUnauthorized
	}
	if !user.Patron {
		return "", ErrUnauthorized
	}
	if s.secretShares == nil {
		return "", fmt.Errorf("secret share not available")
	}
	if _, err := s.items.FindItem(ctx, userID, itemID); err != nil {
		return "", ErrNotFound
	}
	token := randomToken()
	if err := s.secretShares.CreateSecretShare(ctx, ports.StoredSecretShare{
		TokenHash: hashToken(token),
		ItemID:    itemID,
		UserID:    userID,
	}); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) ConsumeSecretShare(ctx context.Context, token string) (domain.Item, error) {
	if s.secretShares == nil {
		return domain.Item{}, ErrNotFound
	}
	share, err := s.secretShares.FindAndDeleteSecretShare(ctx, hashToken(token))
	if err != nil {
		return domain.Item{}, ErrNotFound
	}
	return s.GetItem(ctx, share.UserID, share.ItemID)
}

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b[:])
}

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
