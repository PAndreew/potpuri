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
	mu       sync.Mutex
	users    map[string]domain.User
	items    []ports.StoredItem
	sessions map[string]ports.Session
}

func New() *Store {
	return &Store{
		users:    map[string]domain.User{},
		sessions: map[string]ports.Session{},
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

func (s *Store) CreateItem(ctx context.Context, item ports.StoredItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, item)
	return nil
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
			return nil
		}
	}
	return errors.New("item not found")
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

func cloneItem(item ports.StoredItem) ports.StoredItem {
	item.TitleCiphertext = append([]byte(nil), item.TitleCiphertext...)
	item.BodyCiphertext = append([]byte(nil), item.BodyCiphertext...)
	item.URLCiphertext = append([]byte(nil), item.URLCiphertext...)
	item.SearchTokens = append([]string(nil), item.SearchTokens...)
	item.Tags = append([]string(nil), item.Tags...)
	return item
}
