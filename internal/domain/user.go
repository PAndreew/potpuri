package domain

import "time"

type User struct {
	ID            string
	Email         string
	PasswordHash  string
	TOTPEnabled   bool
	Patron        bool
	EmailVerified bool
	CaptureMode   string // "url" | "meta" | "full"; empty means "url"
	CreatedAt     time.Time
}
