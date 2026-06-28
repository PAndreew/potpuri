package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	feedTokenIssuer   = "potpuri"
	feedTokenAudience = "potpuri-feed"
)

type FeedCredentialIssuer struct {
	secret []byte
}

type FeedClaims struct {
	Issuer   string   `json:"iss"`
	Audience string   `json:"aud"`
	Subject  string   `json:"sub"`
	Scopes   []string `json:"scopes"`
	IssuedAt int64    `json:"iat"`
	Expires  int64    `json:"exp"`
}

func NewFeedCredentialIssuer(secret string) (*FeedCredentialIssuer, error) {
	if len(secret) < 32 {
		return nil, errors.New("feed signing secret must contain at least 32 characters")
	}
	return &FeedCredentialIssuer{secret: []byte(secret)}, nil
}

func (i *FeedCredentialIssuer) IssueFeedCredential(userID string, scopes []string, issuedAt, expiresAt time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(FeedClaims{
		Issuer: feedTokenIssuer, Audience: feedTokenAudience, Subject: userID,
		Scopes: scopes, IssuedAt: issuedAt.Unix(), Expires: expiresAt.Unix(),
	})
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return unsigned + "." + i.sign(unsigned), nil
}

func (i *FeedCredentialIssuer) Verify(token string, now time.Time) (FeedClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return FeedClaims{}, errors.New("invalid feed credential")
	}
	want, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return FeedClaims{}, errors.New("invalid feed credential")
	}
	mac := hmac.New(sha256.New, i.secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(want, mac.Sum(nil)) {
		return FeedClaims{}, errors.New("invalid feed credential signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return FeedClaims{}, errors.New("invalid feed credential")
	}
	var claims FeedClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return FeedClaims{}, errors.New("invalid feed credential")
	}
	if claims.Issuer != feedTokenIssuer || claims.Audience != feedTokenAudience || claims.Subject == "" {
		return FeedClaims{}, errors.New("invalid feed credential claims")
	}
	if claims.IssuedAt > now.Add(time.Minute).Unix() || claims.Expires <= claims.IssuedAt {
		return FeedClaims{}, errors.New("invalid feed credential lifetime")
	}
	if now.Unix() >= claims.Expires {
		return FeedClaims{}, errors.New("feed credential expired")
	}
	return claims, nil
}

func (i *FeedCredentialIssuer) sign(unsigned string) string {
	mac := hmac.New(sha256.New, i.secret)
	_, _ = mac.Write([]byte(unsigned))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
