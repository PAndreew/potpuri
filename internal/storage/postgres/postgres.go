package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/lib/pq"

	"potpuri/internal/domain"
	"potpuri/internal/ports"
)

type Store struct {
	db *sql.DB
}

func Open(databaseURL string) (*Store, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, db.Ping()
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

func (s *Store) CreateUser(ctx context.Context, user domain.User) error {
	_, err := s.db.ExecContext(ctx, `insert into users (id, email, password_hash, created_at) values ($1, $2, $3, $4)`, user.ID, user.Email, user.PasswordHash, user.CreatedAt)
	return err
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (domain.User, error) {
	var user domain.User
	err := s.db.QueryRowContext(ctx, `select id, email, password_hash, created_at from users where email = $1`, email).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)
	return user, err
}

func (s *Store) CreateItem(ctx context.Context, item ports.StoredItem) error {
	_, err := s.db.ExecContext(ctx, `
insert into items (id, user_id, type, title_ciphertext, body_ciphertext, url_ciphertext, search_tokens, tags, created_at)
values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		item.ID, item.UserID, string(item.Type), item.TitleCiphertext, item.BodyCiphertext, item.URLCiphertext, pq.Array(item.SearchTokens), pq.Array(item.Tags), item.CreatedAt)
	return err
}

func (s *Store) ListItems(ctx context.Context, userID string) ([]ports.StoredItem, error) {
	rows, err := s.db.QueryContext(ctx, `
select id, user_id, type, title_ciphertext, body_ciphertext, url_ciphertext, search_tokens, tags, created_at
from items where user_id = $1 order by created_at desc`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanItems(rows)
}

func (s *Store) SearchItems(ctx context.Context, userID string, tokens []string) ([]ports.StoredItem, error) {
	if len(tokens) == 0 {
		return s.ListItems(ctx, userID)
	}
	rows, err := s.db.QueryContext(ctx, `
select id, user_id, type, title_ciphertext, body_ciphertext, url_ciphertext, search_tokens, tags, created_at
from items where user_id = $1 and search_tokens && $2 order by created_at desc`, userID, pq.Array(tokens))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanItems(rows)
}

func (s *Store) CreateSession(ctx context.Context, session ports.Session) error {
	_, err := s.db.ExecContext(ctx, `insert into sessions (token_hash, user_id, expires_at) values ($1, $2, $3)`, session.TokenHash, session.UserID, session.ExpiresAt)
	return err
}

func (s *Store) FindSession(ctx context.Context, tokenHash string) (ports.Session, error) {
	var session ports.Session
	err := s.db.QueryRowContext(ctx, `select token_hash, user_id, expires_at from sessions where token_hash = $1`, tokenHash).Scan(&session.TokenHash, &session.UserID, &session.ExpiresAt)
	return session, err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	result, err := s.db.ExecContext(ctx, `delete from sessions where token_hash = $1`, tokenHash)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("session not found")
	}
	return nil
}

func scanItems(rows *sql.Rows) ([]ports.StoredItem, error) {
	var items []ports.StoredItem
	for rows.Next() {
		var item ports.StoredItem
		var itemType string
		if err := rows.Scan(&item.ID, &item.UserID, &itemType, &item.TitleCiphertext, &item.BodyCiphertext, &item.URLCiphertext, pq.Array(&item.SearchTokens), pq.Array(&item.Tags), &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Type = domain.ItemType(itemType)
		items = append(items, item)
	}
	return items, rows.Err()
}

const schema = `
create table if not exists users (
  id text primary key,
  email text not null unique,
  password_hash text not null,
  created_at timestamptz not null
);

create table if not exists items (
  id text primary key,
  user_id text not null references users(id) on delete cascade,
  type text not null,
  title_ciphertext bytea not null,
  body_ciphertext bytea not null,
  url_ciphertext bytea not null,
  search_tokens text[] not null default '{}',
  tags text[] not null default '{}',
  created_at timestamptz not null
);

create index if not exists items_user_created_idx on items (user_id, created_at desc);
create index if not exists items_search_tokens_idx on items using gin (search_tokens);
create index if not exists items_tags_idx on items using gin (tags);

create table if not exists sessions (
  token_hash text primary key,
  user_id text not null references users(id) on delete cascade,
  expires_at timestamptz not null
);
`

func ParseTags(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return domain.NormalizeTags(strings.Split(raw, ","))
}
