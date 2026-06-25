package domain

import "time"

type User struct {
	ID           string
	Email        string
	PasswordHash string
	TOTPEnabled  bool
	Patron       bool
	CreatedAt    time.Time
}
