package memory

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"potpuri/internal/domain"
	"potpuri/internal/ports"
)

type Store struct {
	mu                 sync.Mutex
	users              map[string]domain.User
	items              []ports.StoredItem
	blobs              []ports.StoredBlob
	sessions           map[string]ports.Session
	apiTokens          map[string]ports.StoredAPIToken
	preauthSessions    map[string]ports.StoredPreauthSession
	totpSecrets        map[string][]byte
	recoveryCodes      map[string]map[string]bool // userID → codeHash → used
	emailVerifications map[string]ports.StoredEmailVerification
	secretShares       map[string]ports.StoredSecretShare
	feedContributions  map[string]domain.FeedContribution
	feedLedger         []domain.FeedLedgerEntry
	feedSettlements    map[string]ports.FeedSettlement
	harnessCredentials map[string]ports.StoredHarnessCredential
}

func New() *Store {
	return &Store{
		users:              map[string]domain.User{},
		sessions:           map[string]ports.Session{},
		apiTokens:          map[string]ports.StoredAPIToken{},
		preauthSessions:    map[string]ports.StoredPreauthSession{},
		totpSecrets:        map[string][]byte{},
		recoveryCodes:      map[string]map[string]bool{},
		emailVerifications: map[string]ports.StoredEmailVerification{},
		secretShares:       map[string]ports.StoredSecretShare{},
		feedContributions:  map[string]domain.FeedContribution{},
		feedSettlements:    map[string]ports.FeedSettlement{},
		harnessCredentials: map[string]ports.StoredHarnessCredential{},
	}
}

func (s *Store) CreateUser(ctx context.Context, user domain.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[user.Email]; exists {
		return errors.New("user already exists")
	}
	s.users[user.Email] = user
	return nil
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[email]
	if !ok {
		return domain.User{}, errors.New("user not found")
	}
	return user, nil
}

func (s *Store) FindUserByID(ctx context.Context, userID string) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.ID == userID {
			return u, nil
		}
	}
	return domain.User{}, errors.New("user not found")
}

func (s *Store) ListUsers(ctx context.Context) ([]domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	users := make([]domain.User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].CreatedAt.After(users[j].CreatedAt)
	})
	return users, nil
}

func (s *Store) SetEmailVerified(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for email, u := range s.users {
		if u.ID == userID {
			u.EmailVerified = true
			s.users[email] = u
			return nil
		}
	}
	return errors.New("user not found")
}

func (s *Store) SetCaptureMode(ctx context.Context, userID string, mode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for email, u := range s.users {
		if u.ID == userID {
			u.CaptureMode = mode
			s.users[email] = u
			return nil
		}
	}
	return errors.New("user not found")
}

func (s *Store) CreateEmailVerification(ctx context.Context, v ports.StoredEmailVerification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emailVerifications[v.TokenHash] = v
	return nil
}

func (s *Store) FindEmailVerification(ctx context.Context, tokenHash string) (ports.StoredEmailVerification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.emailVerifications[tokenHash]
	if !ok {
		return ports.StoredEmailVerification{}, errors.New("verification not found")
	}
	return v, nil
}

func (s *Store) DeleteEmailVerificationsForUser(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, v := range s.emailVerifications {
		if v.UserID == userID {
			delete(s.emailVerifications, hash)
		}
	}
	return nil
}

func (s *Store) SetPatron(ctx context.Context, userID string, patron bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for email, u := range s.users {
		if u.ID == userID {
			u.Patron = patron
			s.users[email] = u
			return nil
		}
	}
	return errors.New("user not found")
}

func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var email string
	for e, u := range s.users {
		if u.ID == userID {
			email = e
			break
		}
	}
	if email == "" {
		return errors.New("user not found")
	}
	delete(s.users, email)
	var items []ports.StoredItem
	var blobs []ports.StoredBlob
	for _, item := range s.items {
		if item.UserID != userID {
			items = append(items, item)
		}
	}
	for _, blob := range s.blobs {
		if blob.UserID != userID {
			blobs = append(blobs, blob)
		}
	}
	s.items = items
	s.blobs = blobs
	for hash, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, hash)
		}
	}
	for hash, tok := range s.apiTokens {
		if tok.UserID == userID {
			delete(s.apiTokens, hash)
		}
	}
	delete(s.feedContributions, userID)
	ledger := s.feedLedger[:0]
	for _, entry := range s.feedLedger {
		if entry.UserID != userID {
			ledger = append(ledger, entry)
		}
	}
	s.feedLedger = ledger
	for jobID, settlement := range s.feedSettlements {
		if settlement.ContributorUserID == userID || settlement.OperatorUserID == userID {
			delete(s.feedSettlements, jobID)
		}
	}
	for hash, credential := range s.harnessCredentials {
		if credential.UserID == userID {
			delete(s.harnessCredentials, hash)
		}
	}
	return nil
}

func (s *Store) CreateHarnessCredential(ctx context.Context, credential ports.StoredHarnessCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.harnessCredentials[credential.TokenHash]; exists {
		return errors.New("harness credential already exists")
	}
	s.harnessCredentials[credential.TokenHash] = credential
	return nil
}

func (s *Store) ListHarnessCredentials(ctx context.Context, userID string) ([]ports.StoredHarnessCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ports.StoredHarnessCredential
	for _, credential := range s.harnessCredentials {
		if credential.UserID == userID {
			out = append(out, credential)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) FindHarnessCredentialByHash(ctx context.Context, tokenHash string) (ports.StoredHarnessCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.harnessCredentials[tokenHash]
	if !ok {
		return ports.StoredHarnessCredential{}, errors.New("harness credential not found")
	}
	return credential, nil
}

func (s *Store) RevokeHarnessCredential(ctx context.Context, userID, credentialID string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, credential := range s.harnessCredentials {
		if credential.ID == credentialID && credential.UserID == userID && credential.RevokedAt == nil {
			t := revokedAt
			credential.RevokedAt = &t
			s.harnessCredentials[hash] = credential
			return nil
		}
	}
	return errors.New("harness credential not found")
}

func (s *Store) TouchHarnessCredential(ctx context.Context, credentialID string, usedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, credential := range s.harnessCredentials {
		if credential.ID == credentialID && credential.RevokedAt == nil {
			t := usedAt
			credential.LastUsedAt = &t
			s.harnessCredentials[hash] = credential
			return nil
		}
	}
	return errors.New("harness credential not found")
}

func (s *Store) SaveFeedContribution(ctx context.Context, contribution domain.FeedContribution) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.feedContributions[contribution.UserID] = contribution
	return nil
}

func (s *Store) FindFeedContribution(ctx context.Context, userID string) (domain.FeedContribution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	contribution, ok := s.feedContributions[userID]
	if !ok {
		return domain.FeedContribution{UserID: userID}, nil
	}
	return contribution, nil
}

func (s *Store) ListFeedContributions(ctx context.Context) ([]domain.FeedContribution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.FeedContribution, 0, len(s.feedContributions))
	for _, contribution := range s.feedContributions {
		out = append(out, contribution)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UserID < out[j].UserID })
	return out, nil
}

func (s *Store) FeedTokensUsedSince(ctx context.Context, userID string, since time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var used int64
	for _, entry := range s.feedLedger {
		if entry.UserID == userID && entry.Kind == "translation_debit" && !entry.CreatedAt.Before(since) {
			used -= entry.Amount
		}
	}
	return used, nil
}

func (s *Store) FeedTokensEarned(ctx context.Context, userID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var earned int64
	for _, entry := range s.feedLedger {
		if entry.UserID == userID && entry.Kind == "translation_reward" {
			earned += entry.Amount
		}
	}
	return earned, nil
}

func (s *Store) ListFeedLedger(ctx context.Context, userID string) ([]domain.FeedLedgerEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []domain.FeedLedgerEntry
	for _, entry := range s.feedLedger {
		if entry.UserID == userID {
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) SettleFeedTranslation(ctx context.Context, settlement ports.FeedSettlement, weekStart time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.feedSettlements[settlement.JobID]; ok {
		if existing.ContributorUserID != settlement.ContributorUserID || existing.OperatorUserID != settlement.OperatorUserID || existing.Tokens != settlement.Tokens {
			return false, errors.New("job already settled with different values")
		}
		return false, nil
	}
	contribution := s.feedContributions[settlement.ContributorUserID]
	var used int64
	for _, entry := range s.feedLedger {
		if entry.UserID == settlement.ContributorUserID && entry.Kind == "translation_debit" && !entry.CreatedAt.Before(weekStart) {
			used -= entry.Amount
		}
	}
	if contribution.WeeklyLimit-used < settlement.Tokens {
		return false, ports.ErrInsufficientFeedContribution
	}
	s.feedSettlements[settlement.JobID] = settlement
	s.feedLedger = append(s.feedLedger,
		domain.FeedLedgerEntry{ID: "fld_" + settlement.JobID + "_debit", UserID: settlement.ContributorUserID, JobID: settlement.JobID, Amount: -settlement.Tokens, Kind: "translation_debit", CreatedAt: settlement.CreatedAt},
		domain.FeedLedgerEntry{ID: "fld_" + settlement.JobID + "_reward", UserID: settlement.OperatorUserID, JobID: settlement.JobID, Amount: settlement.Tokens, Kind: "translation_reward", CreatedAt: settlement.CreatedAt},
	)
	return true, nil
}

func (s *Store) CreateItem(ctx context.Context, item ports.StoredItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, item)
	return nil
}

func (s *Store) FindItem(ctx context.Context, userID string, itemID string) (ports.StoredItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.items {
		if item.UserID == userID && item.ID == itemID {
			return cloneItem(item), nil
		}
	}
	return ports.StoredItem{}, errors.New("item not found")
}

func (s *Store) UpdateItem(ctx context.Context, updated ports.StoredItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, item := range s.items {
		if item.UserID == updated.UserID && item.ID == updated.ID {
			s.items[i] = cloneItem(updated)
			return nil
		}
	}
	return errors.New("item not found")
}

func (s *Store) ListItems(ctx context.Context, userID string) ([]ports.StoredItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ports.StoredItem
	for _, item := range s.items {
		if item.UserID == userID {
			out = append(out, cloneItem(item))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *Store) SearchItems(ctx context.Context, userID string, tokens []string) ([]ports.StoredItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wanted := map[string]bool{}
	for _, token := range tokens {
		wanted[token] = true
	}
	var out []ports.StoredItem
	for _, item := range s.items {
		if item.UserID != userID {
			continue
		}
		for _, token := range item.SearchTokens {
			if wanted[token] {
				out = append(out, cloneItem(item))
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *Store) DeleteItem(ctx context.Context, userID string, itemID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, item := range s.items {
		if item.UserID == userID && item.ID == itemID {
			s.items = append(s.items[:i], s.items[i+1:]...)
			s.deleteBlobsForItemLocked(userID, itemID)
			return nil
		}
	}
	return errors.New("item not found")
}

func (s *Store) CreateBlob(ctx context.Context, blob ports.StoredBlob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs = append(s.blobs, cloneBlob(blob))
	return nil
}

func (s *Store) FindBlob(ctx context.Context, userID string, blobID string) (ports.StoredBlob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, blob := range s.blobs {
		if blob.UserID == userID && blob.ID == blobID {
			return cloneBlob(blob), nil
		}
	}
	return ports.StoredBlob{}, errors.New("blob not found")
}

func (s *Store) ListBlobs(ctx context.Context, userID string, itemID string) ([]ports.StoredBlob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ports.StoredBlob
	for _, blob := range s.blobs {
		if blob.UserID == userID && blob.ItemID == itemID {
			out = append(out, cloneBlob(blob))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (s *Store) TotalBlobSize(ctx context.Context, userID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var total int64
	for _, blob := range s.blobs {
		if blob.UserID == userID {
			total += blob.Size
		}
	}
	return total, nil
}

func (s *Store) DeleteBlobsForItem(ctx context.Context, userID string, itemID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteBlobsForItemLocked(userID, itemID)
	return nil
}

func (s *Store) deleteBlobsForItemLocked(userID string, itemID string) {
	var kept []ports.StoredBlob
	for _, blob := range s.blobs {
		if blob.UserID == userID && blob.ItemID == itemID {
			continue
		}
		kept = append(kept, blob)
	}
	s.blobs = kept
}

func (s *Store) CreateSession(ctx context.Context, session ports.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.TokenHash] = session
	return nil
}

func (s *Store) FindSession(ctx context.Context, tokenHash string) (ports.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[tokenHash]
	if !ok {
		return ports.Session{}, errors.New("session not found")
	}
	return session, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, tokenHash)
	return nil
}

func (s *Store) CreateAPIToken(ctx context.Context, token ports.StoredAPIToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiTokens[token.TokenHash] = token
	return nil
}

func (s *Store) ListAPITokens(ctx context.Context, userID string) ([]ports.StoredAPIToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ports.StoredAPIToken
	for _, t := range s.apiTokens {
		if t.UserID == userID {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) FindAPIToken(ctx context.Context, tokenHash string) (ports.StoredAPIToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.apiTokens[tokenHash]
	if !ok {
		return ports.StoredAPIToken{}, errors.New("api token not found")
	}
	return t, nil
}

func (s *Store) StoreTOTPSecret(ctx context.Context, userID string, secretCiphertext []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totpSecrets[userID] = append([]byte(nil), secretCiphertext...)
	return nil
}

func (s *Store) ActivateTOTP(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for email, u := range s.users {
		if u.ID == userID {
			u.TOTPEnabled = true
			s.users[email] = u
			return nil
		}
	}
	return errors.New("user not found")
}

func (s *Store) DisableTOTP(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for email, u := range s.users {
		if u.ID == userID {
			u.TOTPEnabled = false
			s.users[email] = u
			delete(s.totpSecrets, userID)
			return nil
		}
	}
	return errors.New("user not found")
}

func (s *Store) FindTOTPSecret(ctx context.Context, userID string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ct, ok := s.totpSecrets[userID]
	if !ok {
		return nil, errors.New("no TOTP secret")
	}
	return append([]byte(nil), ct...), nil
}

func (s *Store) CreatePreauthSession(ctx context.Context, session ports.StoredPreauthSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preauthSessions[session.TokenHash] = session
	return nil
}

func (s *Store) FindPreauthSession(ctx context.Context, tokenHash string) (ports.StoredPreauthSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps, ok := s.preauthSessions[tokenHash]
	if !ok {
		return ports.StoredPreauthSession{}, errors.New("preauth session not found")
	}
	return ps, nil
}

func (s *Store) DeletePreauthSession(ctx context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.preauthSessions, tokenHash)
	return nil
}

func (s *Store) StoreRecoveryCodes(ctx context.Context, userID string, codeHashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := make(map[string]bool, len(codeHashes))
	for _, h := range codeHashes {
		m[h] = false
	}
	s.recoveryCodes[userID] = m
	return nil
}

func (s *Store) FindAndConsumeRecoveryCode(ctx context.Context, userID string, codeHash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.recoveryCodes[userID]
	if !ok {
		return false, nil
	}
	used, exists := m[codeHash]
	if !exists || used {
		return false, nil
	}
	m[codeHash] = true
	return true, nil
}

func (s *Store) DeleteRecoveryCodes(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.recoveryCodes, userID)
	return nil
}

func (s *Store) DeleteAPIToken(ctx context.Context, userID string, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, t := range s.apiTokens {
		if t.UserID == userID && t.ID == tokenID {
			delete(s.apiTokens, hash)
			return nil
		}
	}
	return errors.New("api token not found")
}

func (s *Store) CreateSecretShare(ctx context.Context, share ports.StoredSecretShare) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secretShares[share.TokenHash] = share
	return nil
}

func (s *Store) FindAndDeleteSecretShare(ctx context.Context, tokenHash string) (ports.StoredSecretShare, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	share, ok := s.secretShares[tokenHash]
	if !ok {
		return ports.StoredSecretShare{}, errors.New("secret share not found")
	}
	delete(s.secretShares, tokenHash)
	return share, nil
}

func cloneItem(item ports.StoredItem) ports.StoredItem {
	item.TitleCiphertext = append([]byte(nil), item.TitleCiphertext...)
	item.BodyCiphertext = append([]byte(nil), item.BodyCiphertext...)
	item.URLCiphertext = append([]byte(nil), item.URLCiphertext...)
	item.SearchTokens = append([]string(nil), item.SearchTokens...)
	item.Tags = append([]string(nil), item.Tags...)
	return item
}

func cloneBlob(blob ports.StoredBlob) ports.StoredBlob {
	blob.Ciphertext = append([]byte(nil), blob.Ciphertext...)
	return blob
}
