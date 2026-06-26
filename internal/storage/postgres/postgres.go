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
	var totpEnabled sql.NullBool
	err := s.db.QueryRowContext(ctx,
		`select id, email, password_hash, coalesce(totp_enabled, false), coalesce(patron, false), coalesce(email_verified, false), created_at from users where email = $1`, email).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &totpEnabled, &user.Patron, &user.EmailVerified, &user.CreatedAt)
	user.TOTPEnabled = totpEnabled.Bool
	return user, err
}

func (s *Store) FindUserByID(ctx context.Context, userID string) (domain.User, error) {
	var user domain.User
	var totpEnabled sql.NullBool
	err := s.db.QueryRowContext(ctx,
		`select id, email, password_hash, coalesce(totp_enabled, false), coalesce(patron, false), coalesce(email_verified, false), created_at from users where id = $1`, userID).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &totpEnabled, &user.Patron, &user.EmailVerified, &user.CreatedAt)
	user.TOTPEnabled = totpEnabled.Bool
	return user, err
}

func (s *Store) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.db.QueryContext(ctx, `
select id, email, password_hash, coalesce(totp_enabled, false), coalesce(patron, false), coalesce(email_verified, false), created_at
from users order by created_at desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []domain.User
	for rows.Next() {
		var user domain.User
		var totpEnabled sql.NullBool
		if err := rows.Scan(&user.ID, &user.Email, &user.PasswordHash, &totpEnabled, &user.Patron, &user.EmailVerified, &user.CreatedAt); err != nil {
			return nil, err
		}
		user.TOTPEnabled = totpEnabled.Bool
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) SetEmailVerified(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `update users set email_verified = true where id = $1`, userID)
	return err
}

func (s *Store) CreateEmailVerification(ctx context.Context, v ports.StoredEmailVerification) error {
	_, err := s.db.ExecContext(ctx, `insert into email_verifications (token_hash, user_id, expires_at) values ($1, $2, $3)`,
		v.TokenHash, v.UserID, v.ExpiresAt)
	return err
}

func (s *Store) FindEmailVerification(ctx context.Context, tokenHash string) (ports.StoredEmailVerification, error) {
	var v ports.StoredEmailVerification
	err := s.db.QueryRowContext(ctx, `select token_hash, user_id, expires_at from email_verifications where token_hash = $1`, tokenHash).
		Scan(&v.TokenHash, &v.UserID, &v.ExpiresAt)
	return v, err
}

func (s *Store) DeleteEmailVerificationsForUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `delete from email_verifications where user_id = $1`, userID)
	return err
}

func (s *Store) SetPatron(ctx context.Context, userID string, patron bool) error {
	_, err := s.db.ExecContext(ctx, `update users set patron = $2 where id = $1`, userID, patron)
	return err
}

func (s *Store) StoreTOTPSecret(ctx context.Context, userID string, secretCiphertext []byte) error {
	_, err := s.db.ExecContext(ctx, `update users set totp_secret_ciphertext = $2 where id = $1`, userID, secretCiphertext)
	return err
}

func (s *Store) ActivateTOTP(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `update users set totp_enabled = true where id = $1`, userID)
	return err
}

func (s *Store) DisableTOTP(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `update users set totp_enabled = false, totp_secret_ciphertext = null where id = $1`, userID)
	return err
}

func (s *Store) FindTOTPSecret(ctx context.Context, userID string) ([]byte, error) {
	var ct []byte
	err := s.db.QueryRowContext(ctx, `select totp_secret_ciphertext from users where id = $1`, userID).Scan(&ct)
	if err != nil {
		return nil, err
	}
	if ct == nil {
		return nil, errors.New("no TOTP secret")
	}
	return ct, nil
}

func (s *Store) CreatePreauthSession(ctx context.Context, session ports.StoredPreauthSession) error {
	_, err := s.db.ExecContext(ctx, `insert into preauth_sessions (token_hash, user_id, expires_at) values ($1, $2, $3)`,
		session.TokenHash, session.UserID, session.ExpiresAt)
	return err
}

func (s *Store) FindPreauthSession(ctx context.Context, tokenHash string) (ports.StoredPreauthSession, error) {
	var ps ports.StoredPreauthSession
	err := s.db.QueryRowContext(ctx, `select token_hash, user_id, expires_at from preauth_sessions where token_hash = $1`, tokenHash).
		Scan(&ps.TokenHash, &ps.UserID, &ps.ExpiresAt)
	return ps, err
}

func (s *Store) DeletePreauthSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `delete from preauth_sessions where token_hash = $1`, tokenHash)
	return err
}

func (s *Store) StoreRecoveryCodes(ctx context.Context, userID string, codeHashes []string) error {
	_, err := s.db.ExecContext(ctx, `delete from totp_recovery_codes where user_id = $1`, userID)
	if err != nil {
		return err
	}
	for _, h := range codeHashes {
		if _, err := s.db.ExecContext(ctx, `insert into totp_recovery_codes (id, user_id, code_hash) values ($1, $2, $3)`,
			"rc_"+h[:8], userID, h); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) FindAndConsumeRecoveryCode(ctx context.Context, userID string, codeHash string) (bool, error) {
	result, err := s.db.ExecContext(ctx,
		`update totp_recovery_codes set used_at = now() where user_id = $1 and code_hash = $2 and used_at is null`,
		userID, codeHash)
	if err != nil {
		return false, err
	}
	rows, _ := result.RowsAffected()
	return rows > 0, nil
}

func (s *Store) DeleteRecoveryCodes(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `delete from totp_recovery_codes where user_id = $1`, userID)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	result, err := s.db.ExecContext(ctx, `delete from users where id = $1`, userID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("user not found")
	}
	return nil
}

func (s *Store) CreateItem(ctx context.Context, item ports.StoredItem) error {
	if item.SearchTokens == nil {
		item.SearchTokens = []string{}
	}
	if item.Tags == nil {
		item.Tags = []string{}
	}
	_, err := s.db.ExecContext(ctx, `
insert into items (id, user_id, type, title_ciphertext, body_ciphertext, url_ciphertext, search_tokens, tags, created_at)
values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		item.ID, item.UserID, string(item.Type), item.TitleCiphertext, item.BodyCiphertext, item.URLCiphertext, pq.Array(item.SearchTokens), pq.Array(item.Tags), item.CreatedAt)
	return err
}

func (s *Store) FindItem(ctx context.Context, userID string, itemID string) (ports.StoredItem, error) {
	row := s.db.QueryRowContext(ctx, `
select id, user_id, type, title_ciphertext, body_ciphertext, url_ciphertext, search_tokens, tags, created_at
from items where user_id = $1 and id = $2`, userID, itemID)
	var item ports.StoredItem
	var itemType string
	if err := row.Scan(&item.ID, &item.UserID, &itemType, &item.TitleCiphertext, &item.BodyCiphertext, &item.URLCiphertext, pq.Array(&item.SearchTokens), pq.Array(&item.Tags), &item.CreatedAt); err != nil {
		return ports.StoredItem{}, err
	}
	item.Type = domain.ItemType(itemType)
	return item, nil
}

func (s *Store) UpdateItem(ctx context.Context, item ports.StoredItem) error {
	if item.SearchTokens == nil {
		item.SearchTokens = []string{}
	}
	if item.Tags == nil {
		item.Tags = []string{}
	}
	result, err := s.db.ExecContext(ctx, `
update items
set type = $3,
    title_ciphertext = $4,
    body_ciphertext = $5,
    url_ciphertext = $6,
    search_tokens = $7,
    tags = $8
where user_id = $1 and id = $2`,
		item.UserID, item.ID, string(item.Type), item.TitleCiphertext, item.BodyCiphertext, item.URLCiphertext, pq.Array(item.SearchTokens), pq.Array(item.Tags))
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("item not found")
	}
	return nil
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

func (s *Store) DeleteItem(ctx context.Context, userID string, itemID string) error {
	result, err := s.db.ExecContext(ctx, `delete from items where user_id = $1 and id = $2`, userID, itemID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("item not found")
	}
	return nil
}

func (s *Store) CreateBlob(ctx context.Context, blob ports.StoredBlob) error {
	var ciphertext interface{}
	if len(blob.Ciphertext) > 0 {
		ciphertext = blob.Ciphertext
	}
	_, err := s.db.ExecContext(ctx, `
insert into blobs (id, user_id, item_id, filename, content_type, size_bytes, ciphertext, created_at)
values ($1, $2, $3, $4, $5, $6, $7, $8)`,
		blob.ID, blob.UserID, blob.ItemID, blob.Filename, blob.ContentType, blob.Size, ciphertext, blob.CreatedAt)
	return err
}

func (s *Store) FindBlob(ctx context.Context, userID string, blobID string) (ports.StoredBlob, error) {
	var blob ports.StoredBlob
	var ciphertext []byte
	err := s.db.QueryRowContext(ctx, `
select id, user_id, item_id, filename, content_type, size_bytes, ciphertext, created_at
from blobs where user_id = $1 and id = $2`, userID, blobID).
		Scan(&blob.ID, &blob.UserID, &blob.ItemID, &blob.Filename, &blob.ContentType, &blob.Size, &ciphertext, &blob.CreatedAt)
	blob.Ciphertext = ciphertext
	return blob, err
}

func (s *Store) ListBlobs(ctx context.Context, userID string, itemID string) ([]ports.StoredBlob, error) {
	rows, err := s.db.QueryContext(ctx, `
select id, user_id, item_id, filename, content_type, size_bytes, ciphertext, created_at
from blobs where user_id = $1 and item_id = $2 order by created_at asc`, userID, itemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var blobs []ports.StoredBlob
	for rows.Next() {
		var blob ports.StoredBlob
		var ciphertext []byte
		if err := rows.Scan(&blob.ID, &blob.UserID, &blob.ItemID, &blob.Filename, &blob.ContentType, &blob.Size, &ciphertext, &blob.CreatedAt); err != nil {
			return nil, err
		}
		blob.Ciphertext = ciphertext
		blobs = append(blobs, blob)
	}
	return blobs, rows.Err()
}

func (s *Store) DeleteBlobsForItem(ctx context.Context, userID string, itemID string) error {
	_, err := s.db.ExecContext(ctx, `delete from blobs where user_id = $1 and item_id = $2`, userID, itemID)
	return err
}

func (s *Store) TotalBlobSize(ctx context.Context, userID string) (int64, error) {
	var total int64
	err := s.db.QueryRowContext(ctx, `select coalesce(sum(size_bytes), 0) from blobs where user_id = $1`, userID).Scan(&total)
	return total, err
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

func (s *Store) CreateAPIToken(ctx context.Context, token ports.StoredAPIToken) error {
	_, err := s.db.ExecContext(ctx, `insert into api_tokens (id, user_id, name, token_hash, created_at) values ($1, $2, $3, $4, $5)`,
		token.ID, token.UserID, token.Name, token.TokenHash, token.CreatedAt)
	return err
}

func (s *Store) ListAPITokens(ctx context.Context, userID string) ([]ports.StoredAPIToken, error) {
	rows, err := s.db.QueryContext(ctx, `select id, user_id, name, token_hash, created_at from api_tokens where user_id = $1 order by created_at asc`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []ports.StoredAPIToken
	for rows.Next() {
		var t ports.StoredAPIToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.TokenHash, &t.CreatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *Store) FindAPIToken(ctx context.Context, tokenHash string) (ports.StoredAPIToken, error) {
	var t ports.StoredAPIToken
	err := s.db.QueryRowContext(ctx, `select id, user_id, name, token_hash, created_at from api_tokens where token_hash = $1`, tokenHash).
		Scan(&t.ID, &t.UserID, &t.Name, &t.TokenHash, &t.CreatedAt)
	return t, err
}

func (s *Store) DeleteAPIToken(ctx context.Context, userID string, tokenID string) error {
	result, err := s.db.ExecContext(ctx, `delete from api_tokens where user_id = $1 and id = $2`, userID, tokenID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("api token not found")
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

create table if not exists blobs (
  id text primary key,
  user_id text not null references users(id) on delete cascade,
  item_id text not null references items(id) on delete cascade,
  filename text not null,
  content_type text not null,
  size_bytes bigint not null,
  ciphertext bytea,
  created_at timestamptz not null
);

-- allow existing deployments that had NOT NULL to accept NULL ciphertext for R2-backed blobs
do $$ begin
  alter table blobs alter column ciphertext drop not null;
exception when others then null;
end $$;

create index if not exists blobs_user_item_idx on blobs (user_id, item_id);

create table if not exists sessions (
  token_hash text primary key,
  user_id text not null references users(id) on delete cascade,
  expires_at timestamptz not null
);

create table if not exists api_tokens (
  id text primary key,
  user_id text not null references users(id) on delete cascade,
  name text not null,
  token_hash text not null unique,
  created_at timestamptz not null
);

create index if not exists api_tokens_user_idx on api_tokens (user_id);

do $$ begin alter table users add column totp_secret_ciphertext bytea; exception when others then null; end $$;
do $$ begin alter table users add column totp_enabled boolean not null default false; exception when others then null; end $$;
do $$ begin alter table users add column patron boolean not null default false; exception when others then null; end $$;
do $$ begin alter table users add column email_verified boolean not null default false; exception when others then null; end $$;

create table if not exists email_verifications (
  token_hash text primary key,
  user_id text not null references users(id) on delete cascade,
  expires_at timestamptz not null
);

create table if not exists preauth_sessions (
  token_hash text primary key,
  user_id text not null references users(id) on delete cascade,
  expires_at timestamptz not null
);

create table if not exists totp_recovery_codes (
  id text primary key,
  user_id text not null references users(id) on delete cascade,
  code_hash text not null unique,
  used_at timestamptz
);
`

func ParseTags(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return domain.NormalizeTags(strings.Split(raw, ","))
}
