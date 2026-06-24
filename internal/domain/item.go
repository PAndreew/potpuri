package domain

import (
	"strings"
	"time"
)

type ItemType string

const (
	ItemTypeNote  ItemType = "note"
	ItemTypeURL   ItemType = "url"
	ItemTypeFile  ItemType = "file"
	ItemTypePhoto ItemType = "photo"
)

type Item struct {
	ID        string
	UserID    string
	Type      ItemType
	Title     string
	Body      string
	SourceURL string
	Tags      []string
	CreatedAt time.Time
}

func NormalizeTags(tags []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, tag := range tags {
		tag = strings.Trim(strings.ToLower(tag), " \t\r\n#")
		tag = strings.ReplaceAll(tag, " ", "-")
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		out = append(out, tag)
	}
	return out
}
