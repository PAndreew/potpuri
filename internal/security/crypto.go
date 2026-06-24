package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strings"
)

type Cipher struct {
	gcm       cipher.AEAD
	searchKey []byte
}

func NewCipher(secret []byte) (*Cipher, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("encryption key must be at least 32 bytes")
	}
	block, err := aes.NewCipher(secret[:32])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	searchKey := sha256.Sum256(append([]byte("potpuri-search:"), secret...))
	return &Cipher{gcm: gcm, searchKey: searchKey[:]}, nil
}

func NewCipherFromBase64(secret string) (*Cipher, error) {
	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		key = []byte(secret)
	}
	return NewCipher(key)
}

func (c *Cipher) SealString(plaintext string) ([]byte, error) {
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return c.gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

func (c *Cipher) OpenString(ciphertext []byte) (string, error) {
	if len(ciphertext) < c.gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:c.gcm.NonceSize()]
	body := ciphertext[c.gcm.NonceSize():]
	plaintext, err := c.gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

var wordRE = regexp.MustCompile(`[a-z0-9]+`)

func (c *Cipher) SearchTokens(parts ...string) []string {
	seen := map[string]bool{}
	var tokens []string
	for _, part := range parts {
		for _, word := range wordRE.FindAllString(strings.ToLower(part), -1) {
			if len(word) < 2 || seen[word] {
				continue
			}
			seen[word] = true
			mac := hmac.New(sha256.New, c.searchKey)
			_, _ = mac.Write([]byte(word))
			tokens = append(tokens, base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
		}
	}
	return tokens
}
