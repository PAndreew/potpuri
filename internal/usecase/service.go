package usecase

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"potpuri/internal/domain"
	"potpuri/internal/ports"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrNotFound           = errors.New("not found")
)

type Service struct {
	users    ports.UserRepository
	items    ports.ItemRepository
	sessions ports.SessionRepository
	cipher   ports.ItemCipher
	hasher   ports.PasswordHasher
	now      func() time.Time
}

type NewServiceParams struct {
	Users    ports.UserRepository
	Items    ports.ItemRepository
	Sessions ports.SessionRepository
	Cipher   ports.ItemCipher
	Hasher   ports.PasswordHasher
	Now      func() time.Time
}

func NewService(params NewServiceParams) *Service {
	now := params.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		users:    params.Users,
		items:    params.Items,
		sessions: params.Sessions,
		cipher:   params.Cipher,
		hasher:   params.Hasher,
		now:      now,
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
	return user, s.users.CreateUser(ctx, user)
}

func (s *Service) Login(ctx context.Context, email, password string) (string, error) {
	user, err := s.users.FindUserByEmail(ctx, strings.TrimSpace(strings.ToLower(email)))
	if err != nil || !s.hasher.Verify(user.PasswordHash, password) {
		return "", ErrInvalidCredentials
	}
	token := randomToken()
	session := ports.Session{
		TokenHash: hashToken(token),
		UserID:    user.ID,
		ExpiresAt: s.now().UTC().Add(30 * 24 * time.Hour),
	}
	if err := s.sessions.CreateSession(ctx, session); err != nil {
		return "", err
	}
	return token, nil
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

type CreateItemInput struct {
	UserID    string
	Type      domain.ItemType
	Title     string
	Body      string
	SourceURL string
	Tags      []string
}

func (s *Service) CreateItem(ctx context.Context, input CreateItemInput) (domain.Item, error) {
	if input.UserID == "" {
		return domain.Item{}, ErrUnauthorized
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
		SearchTokens:    s.cipher.SearchTokens(item.Title, item.Body, item.SourceURL, strings.Join(item.Tags, " ")),
		Tags:            item.Tags,
		CreatedAt:       item.CreatedAt,
	}
	return item, s.items.CreateItem(ctx, stored)
}

func (s *Service) ListItems(ctx context.Context, userID string) ([]domain.Item, error) {
	if userID == "" {
		return nil, ErrUnauthorized
	}
	stored, err := s.items.ListItems(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.decryptItems(stored)
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
	return s.decryptItems(stored)
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

func (s *Service) decryptItems(stored []ports.StoredItem) ([]domain.Item, error) {
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
		items = append(items, domain.Item{
			ID:        storedItem.ID,
			UserID:    storedItem.UserID,
			Type:      storedItem.Type,
			Title:     title,
			Body:      body,
			SourceURL: sourceURL,
			Tags:      storedItem.Tags,
			CreatedAt: storedItem.CreatedAt,
		})
	}
	return items, nil
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
