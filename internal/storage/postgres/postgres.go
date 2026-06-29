package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

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
		`select id, email, password_hash, coalesce(totp_enabled, false), coalesce(patron, false), coalesce(email_verified, false), coalesce(capture_mode, 'url'), created_at from users where email = $1`, email).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &totpEnabled, &user.Patron, &user.EmailVerified, &user.CaptureMode, &user.CreatedAt)
	user.TOTPEnabled = totpEnabled.Bool
	return user, err
}

func (s *Store) FindUserByID(ctx context.Context, userID string) (domain.User, error) {
	var user domain.User
	var totpEnabled sql.NullBool
	err := s.db.QueryRowContext(ctx,
		`select id, email, password_hash, coalesce(totp_enabled, false), coalesce(patron, false), coalesce(email_verified, false), coalesce(capture_mode, 'url'), created_at from users where id = $1`, userID).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &totpEnabled, &user.Patron, &user.EmailVerified, &user.CaptureMode, &user.CreatedAt)
	user.TOTPEnabled = totpEnabled.Bool
	return user, err
}

func (s *Store) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.db.QueryContext(ctx, `
select id, email, password_hash, coalesce(totp_enabled, false), coalesce(patron, false), coalesce(email_verified, false), coalesce(capture_mode, 'url'), created_at
from users order by created_at desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []domain.User
	for rows.Next() {
		var user domain.User
		var totpEnabled sql.NullBool
		if err := rows.Scan(&user.ID, &user.Email, &user.PasswordHash, &totpEnabled, &user.Patron, &user.EmailVerified, &user.CaptureMode, &user.CreatedAt); err != nil {
			return nil, err
		}
		user.TOTPEnabled = totpEnabled.Bool
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) SetCaptureMode(ctx context.Context, userID string, mode string) error {
	_, err := s.db.ExecContext(ctx, `update users set capture_mode = $2 where id = $1`, userID, mode)
	return err
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
do $$ begin alter table users add column capture_mode text not null default 'url'; exception when others then null; end $$;

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

create table if not exists secret_shares (
  token_hash text primary key,
  item_id text not null,
  user_id text not null references users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists feed_contributions (
  user_id text primary key references users(id) on delete cascade,
  weekly_limit bigint not null check (weekly_limit >= 0),
  updated_at timestamptz not null
);

create table if not exists feed_settlements (
  job_id text primary key,
  contributor_user_id text not null references users(id) on delete cascade,
  operator_user_id text not null references users(id) on delete cascade,
  tokens bigint not null check (tokens > 0),
  created_at timestamptz not null
);

create table if not exists feed_token_ledger (
  id text primary key,
  user_id text not null references users(id) on delete cascade,
  job_id text not null references feed_settlements(job_id) on delete cascade,
  amount bigint not null,
  kind text not null check (kind in ('translation_debit', 'translation_reward')),
  created_at timestamptz not null,
  unique (user_id, job_id, kind)
);

create index if not exists feed_token_ledger_user_created_idx
  on feed_token_ledger (user_id, created_at desc);

create table if not exists harness_credentials (
  id text primary key,
  user_id text not null references users(id) on delete cascade,
  name text not null,
  provider text not null check (provider in ('codex', 'claude-code')),
  key_hint text not null,
  token_hash text not null unique,
  created_at timestamptz not null,
  last_used_at timestamptz,
  revoked_at timestamptz
);

create index if not exists harness_credentials_user_created_idx
  on harness_credentials (user_id, created_at desc);
`

func (s *Store) CreateSecretShare(ctx context.Context, share ports.StoredSecretShare) error {
	_, err := s.db.ExecContext(ctx,
		`insert into secret_shares (token_hash, item_id, user_id) values ($1, $2, $3)`,
		share.TokenHash, share.ItemID, share.UserID)
	return err
}

func (s *Store) FindAndDeleteSecretShare(ctx context.Context, tokenHash string) (ports.StoredSecretShare, error) {
	var share ports.StoredSecretShare
	err := s.db.QueryRowContext(ctx,
		`delete from secret_shares where token_hash = $1 returning token_hash, item_id, user_id`,
		tokenHash).Scan(&share.TokenHash, &share.ItemID, &share.UserID)
	return share, err
}

func (s *Store) SaveFeedContribution(ctx context.Context, contribution domain.FeedContribution) error {
	_, err := s.db.ExecContext(ctx, `
insert into feed_contributions (user_id, weekly_limit, updated_at) values ($1, $2, $3)
on conflict (user_id) do update set weekly_limit = excluded.weekly_limit, updated_at = excluded.updated_at`,
		contribution.UserID, contribution.WeeklyLimit, contribution.UpdatedAt)
	return err
}

func (s *Store) FindFeedContribution(ctx context.Context, userID string) (domain.FeedContribution, error) {
	var contribution domain.FeedContribution
	err := s.db.QueryRowContext(ctx, `
select user_id, weekly_limit, updated_at from feed_contributions where user_id = $1`, userID).
		Scan(&contribution.UserID, &contribution.WeeklyLimit, &contribution.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.FeedContribution{UserID: userID}, nil
	}
	return contribution, err
}

func (s *Store) ListFeedContributions(ctx context.Context) ([]domain.FeedContribution, error) {
	rows, err := s.db.QueryContext(ctx, `
select user_id, weekly_limit, updated_at from feed_contributions where weekly_limit > 0 order by user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.FeedContribution
	for rows.Next() {
		var contribution domain.FeedContribution
		if err := rows.Scan(&contribution.UserID, &contribution.WeeklyLimit, &contribution.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, contribution)
	}
	return out, rows.Err()
}

func (s *Store) FeedTokensUsedSince(ctx context.Context, userID string, since time.Time) (int64, error) {
	var used int64
	err := s.db.QueryRowContext(ctx, `
select coalesce(-sum(amount), 0) from feed_token_ledger
where user_id = $1 and kind = 'translation_debit' and created_at >= $2`, userID, since).Scan(&used)
	return used, err
}

func (s *Store) FeedTokensEarned(ctx context.Context, userID string) (int64, error) {
	var earned int64
	err := s.db.QueryRowContext(ctx, `
select coalesce(sum(amount), 0) from feed_token_ledger
where user_id = $1 and kind = 'translation_reward'`, userID).Scan(&earned)
	return earned, err
}

func (s *Store) ListFeedLedger(ctx context.Context, userID string) ([]domain.FeedLedgerEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
select id, user_id, job_id, amount, kind, created_at
from feed_token_ledger where user_id = $1 order by created_at desc, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.FeedLedgerEntry
	for rows.Next() {
		var entry domain.FeedLedgerEntry
		if err := rows.Scan(&entry.ID, &entry.UserID, &entry.JobID, &entry.Amount, &entry.Kind, &entry.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func (s *Store) SettleFeedTranslation(ctx context.Context, settlement ports.FeedSettlement, weekStart time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `select pg_advisory_xact_lock(hashtextextended($1, 0))`, settlement.JobID); err != nil {
		return false, err
	}

	var existing ports.FeedSettlement
	err = tx.QueryRowContext(ctx, `
select job_id, contributor_user_id, operator_user_id, tokens, created_at
from feed_settlements where job_id = $1`, settlement.JobID).
		Scan(&existing.JobID, &existing.ContributorUserID, &existing.OperatorUserID, &existing.Tokens, &existing.CreatedAt)
	if err == nil {
		if existing.ContributorUserID != settlement.ContributorUserID || existing.OperatorUserID != settlement.OperatorUserID || existing.Tokens != settlement.Tokens {
			return false, errors.New("job already settled with different values")
		}
		return false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}

	var weeklyLimit int64
	if err := tx.QueryRowContext(ctx, `
select weekly_limit from feed_contributions where user_id = $1 for update`, settlement.ContributorUserID).
		Scan(&weeklyLimit); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ports.ErrInsufficientFeedContribution
		}
		return false, err
	}
	var used int64
	if err := tx.QueryRowContext(ctx, `
select coalesce(-sum(amount), 0) from feed_token_ledger
where user_id = $1 and kind = 'translation_debit' and created_at >= $2`, settlement.ContributorUserID, weekStart).
		Scan(&used); err != nil {
		return false, err
	}
	if weeklyLimit-used < settlement.Tokens {
		return false, ports.ErrInsufficientFeedContribution
	}
	if _, err := tx.ExecContext(ctx, `
insert into feed_settlements (job_id, contributor_user_id, operator_user_id, tokens, created_at)
values ($1, $2, $3, $4, $5)`, settlement.JobID, settlement.ContributorUserID, settlement.OperatorUserID, settlement.Tokens, settlement.CreatedAt); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
insert into feed_token_ledger (id, user_id, job_id, amount, kind, created_at) values
($1, $2, $3, $4, 'translation_debit', $5),
($6, $7, $3, $8, 'translation_reward', $5)`,
		"fld_"+settlement.JobID+"_debit", settlement.ContributorUserID, settlement.JobID, -settlement.Tokens, settlement.CreatedAt,
		"fld_"+settlement.JobID+"_reward", settlement.OperatorUserID, settlement.Tokens); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) CreateHarnessCredential(ctx context.Context, credential ports.StoredHarnessCredential) error {
	_, err := s.db.ExecContext(ctx, `
insert into harness_credentials (id, user_id, name, provider, key_hint, token_hash, created_at)
values ($1, $2, $3, $4, $5, $6, $7)`,
		credential.ID, credential.UserID, credential.Name, credential.Provider,
		credential.KeyHint, credential.TokenHash, credential.CreatedAt)
	return err
}

func (s *Store) ListHarnessCredentials(ctx context.Context, userID string) ([]ports.StoredHarnessCredential, error) {
	rows, err := s.db.QueryContext(ctx, `
select id, user_id, name, provider, key_hint, token_hash, created_at, last_used_at, revoked_at
from harness_credentials where user_id = $1 order by created_at desc`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.StoredHarnessCredential
	for rows.Next() {
		credential, err := scanHarnessCredential(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, credential)
	}
	return out, rows.Err()
}

func (s *Store) FindHarnessCredentialByHash(ctx context.Context, tokenHash string) (ports.StoredHarnessCredential, error) {
	row := s.db.QueryRowContext(ctx, `
select id, user_id, name, provider, key_hint, token_hash, created_at, last_used_at, revoked_at
from harness_credentials where token_hash = $1`, tokenHash)
	return scanHarnessCredential(row.Scan)
}

func (s *Store) RevokeHarnessCredential(ctx context.Context, userID, credentialID string, revokedAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `
update harness_credentials set revoked_at = $3
where user_id = $1 and id = $2 and revoked_at is null`, userID, credentialID, revokedAt)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("harness credential not found")
	}
	return nil
}

func (s *Store) TouchHarnessCredential(ctx context.Context, credentialID string, usedAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `
update harness_credentials set last_used_at = $2 where id = $1 and revoked_at is null`, credentialID, usedAt)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("harness credential not found")
	}
	return nil
}

type rowScanner func(dest ...any) error

func scanHarnessCredential(scan rowScanner) (ports.StoredHarnessCredential, error) {
	var credential ports.StoredHarnessCredential
	var lastUsed, revoked sql.NullTime
	err := scan(
		&credential.ID, &credential.UserID, &credential.Name, &credential.Provider,
		&credential.KeyHint, &credential.TokenHash, &credential.CreatedAt, &lastUsed, &revoked,
	)
	if err != nil {
		return ports.StoredHarnessCredential{}, err
	}
	if lastUsed.Valid {
		credential.LastUsedAt = &lastUsed.Time
	}
	if revoked.Valid {
		credential.RevokedAt = &revoked.Time
	}
	return credential, nil
}

func ParseTags(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return domain.NormalizeTags(strings.Split(raw, ","))
}
