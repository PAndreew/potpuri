package memory

import (
	"context"
	"errors"
	"sort"
	"sync"

	"potpuri/internal/domain"
	"potpuri/internal/ports"
)

type Store struct {
	mu              sync.Mutex
	users           map[string]domain.User
	items           []ports.StoredItem
	blobs           []ports.StoredBlob
	sessions        map[string]ports.Session
	apiTokens       map[string]ports.StoredAPIToken
	preauthSessions map[string]ports.StoredPreauthSession
	totpSecrets     map[string][]byte
	recoveryCodes   map[string]map[string]bool // userID → codeHash → used
}

func New() *Store {
	return &Store{
		users:           map[string]domain.User{},
		sessions:        map[string]ports.Session{},
		apiTokens:       map[string]ports.StoredAPIToken{},
		preauthSessions: map[string]ports.StoredPreauthSession{},
		totpSecrets:     map[string][]byte{},
		recoveryCodes:   map[string]map[string]bool{},
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
	return nil
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
