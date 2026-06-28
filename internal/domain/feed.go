package domain

import "time"

type FeedContribution struct {
	UserID      string
	WeeklyLimit int64
	UpdatedAt   time.Time
}

type FeedLedgerEntry struct {
	ID        string
	UserID    string
	JobID     string
	Amount    int64
	Kind      string
	CreatedAt time.Time
}
