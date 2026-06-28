package usecase

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"potpuri/internal/domain"
	"potpuri/internal/ports"
)

const MaxWeeklyFeedContribution int64 = 10_000_000

var feedLanguageRE = regexp.MustCompile(`^[A-Za-z]{2,8}([_-][A-Za-z0-9]{1,8})*$`)

type FeedContributionStatus struct {
	UserID       string `json:"user_id"`
	WeeklyLimit  int64  `json:"weekly_limit"`
	UsedThisWeek int64  `json:"used_this_week"`
	Remaining    int64  `json:"remaining"`
	Earned       int64  `json:"earned"`
}

func (s *Service) UpdateFeedContribution(ctx context.Context, userID string, weeklyLimit int64) error {
	if strings.TrimSpace(userID) == "" {
		return ErrUnauthorized
	}
	if weeklyLimit < 0 || weeklyLimit > MaxWeeklyFeedContribution {
		return fmt.Errorf("weekly contribution must be between 0 and %d tokens", MaxWeeklyFeedContribution)
	}
	if s.feed == nil {
		return fmt.Errorf("feed contributions are not configured")
	}
	if _, err := s.users.FindUserByID(ctx, userID); err != nil {
		return ErrUnauthorized
	}
	return s.feed.SaveFeedContribution(ctx, domain.FeedContribution{
		UserID: userID, WeeklyLimit: weeklyLimit, UpdatedAt: s.now().UTC(),
	})
}

func (s *Service) GetFeedContribution(ctx context.Context, userID string) (FeedContributionStatus, error) {
	if strings.TrimSpace(userID) == "" {
		return FeedContributionStatus{}, ErrUnauthorized
	}
	if s.feed == nil {
		return FeedContributionStatus{}, fmt.Errorf("feed contributions are not configured")
	}
	contribution, err := s.feed.FindFeedContribution(ctx, userID)
	if err != nil {
		return FeedContributionStatus{}, err
	}
	used, err := s.feed.FeedTokensUsedSince(ctx, userID, isoWeekStart(s.now().UTC()))
	if err != nil {
		return FeedContributionStatus{}, err
	}
	earned, err := s.feed.FeedTokensEarned(ctx, userID)
	if err != nil {
		return FeedContributionStatus{}, err
	}
	remaining := contribution.WeeklyLimit - used
	if remaining < 0 {
		remaining = 0
	}
	return FeedContributionStatus{
		UserID: userID, WeeklyLimit: contribution.WeeklyLimit, UsedThisWeek: used,
		Remaining: remaining, Earned: earned,
	}, nil
}

type FeedContributionCapacity struct {
	UserID    string `json:"user_id"`
	Remaining int64  `json:"remaining"`
}

func (s *Service) ListFeedContributionCapacity(ctx context.Context) ([]FeedContributionCapacity, error) {
	if s.feed == nil {
		return nil, fmt.Errorf("feed contributions are not configured")
	}
	contributions, err := s.feed.ListFeedContributions(ctx)
	if err != nil {
		return nil, err
	}
	weekStart := isoWeekStart(s.now().UTC())
	out := make([]FeedContributionCapacity, 0, len(contributions))
	for _, contribution := range contributions {
		used, err := s.feed.FeedTokensUsedSince(ctx, contribution.UserID, weekStart)
		if err != nil {
			return nil, err
		}
		remaining := contribution.WeeklyLimit - used
		if remaining > 0 {
			out = append(out, FeedContributionCapacity{UserID: contribution.UserID, Remaining: remaining})
		}
	}
	return out, nil
}

type SettleFeedTranslationInput struct {
	JobID             string `json:"job_id"`
	ContributorUserID string `json:"contributor_user_id"`
	OperatorUserID    string `json:"operator_user_id"`
	Tokens            int64  `json:"tokens"`
}

type FeedCredential struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) IssueFeedCredential(ctx context.Context, userID string) (FeedCredential, error) {
	if strings.TrimSpace(userID) == "" {
		return FeedCredential{}, ErrUnauthorized
	}
	if s.feedCredentials == nil {
		return FeedCredential{}, fmt.Errorf("feed credentials are not configured")
	}
	if _, err := s.users.FindUserByID(ctx, userID); err != nil {
		return FeedCredential{}, ErrUnauthorized
	}
	now := s.now().UTC()
	expiresAt := now.Add(15 * time.Minute)
	token, err := s.feedCredentials.IssueFeedCredential(userID, []string{
		"feed:read", "translation:request", "potpuri:save",
	}, now, expiresAt)
	if err != nil {
		return FeedCredential{}, err
	}
	return FeedCredential{Token: token, ExpiresAt: expiresAt}, nil
}

type SaveFeedTranslationInput struct {
	UserID      string `json:"-"`
	Title       string `json:"title"`
	Markdown    string `json:"markdown"`
	OriginalURL string `json:"original_url"`
	Language    string `json:"language"`
}

func (s *Service) SaveFeedTranslation(ctx context.Context, input SaveFeedTranslationInput) (domain.Item, error) {
	input.Title = strings.TrimSpace(input.Title)
	input.OriginalURL = strings.TrimSpace(input.OriginalURL)
	input.Language = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(input.Language), "_", "-"))
	if input.UserID == "" {
		return domain.Item{}, ErrUnauthorized
	}
	if input.Title == "" || strings.TrimSpace(input.Markdown) == "" {
		return domain.Item{}, fmt.Errorf("title and translated Markdown are required")
	}
	parsedURL, err := url.ParseRequestURI(input.OriginalURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		return domain.Item{}, fmt.Errorf("a valid original HTTP URL is required")
	}
	if !feedLanguageRE.MatchString(input.Language) {
		return domain.Item{}, fmt.Errorf("a valid target language is required")
	}
	return s.CreateItem(ctx, CreateItemInput{
		UserID: input.UserID, Type: domain.ItemTypeURL, Title: input.Title,
		Body: input.Markdown, SourceURL: input.OriginalURL,
		Tags: []string{"feed", "translation", "language-" + input.Language},
	})
}

func (s *Service) SettleFeedTranslation(ctx context.Context, input SettleFeedTranslationInput) (bool, error) {
	input.JobID = strings.TrimSpace(input.JobID)
	input.ContributorUserID = strings.TrimSpace(input.ContributorUserID)
	input.OperatorUserID = strings.TrimSpace(input.OperatorUserID)
	if input.JobID == "" || input.ContributorUserID == "" || input.OperatorUserID == "" || input.Tokens <= 0 {
		return false, fmt.Errorf("job, contributor, operator, and positive token count are required")
	}
	if len(input.JobID) > 200 {
		return false, fmt.Errorf("job ID must not exceed 200 characters")
	}
	if input.Tokens > MaxWeeklyFeedContribution {
		return false, fmt.Errorf("settlement exceeds maximum token count")
	}
	if s.feed == nil {
		return false, fmt.Errorf("feed contributions are not configured")
	}
	if _, err := s.users.FindUserByID(ctx, input.ContributorUserID); err != nil {
		return false, fmt.Errorf("contributor: %w", ErrNotFound)
	}
	if _, err := s.users.FindUserByID(ctx, input.OperatorUserID); err != nil {
		return false, fmt.Errorf("operator: %w", ErrNotFound)
	}
	now := s.now().UTC()
	return s.feed.SettleFeedTranslation(ctx, ports.FeedSettlement{
		JobID: input.JobID, ContributorUserID: input.ContributorUserID,
		OperatorUserID: input.OperatorUserID, Tokens: input.Tokens, CreatedAt: now,
	}, isoWeekStart(now))
}

func (s *Service) ListFeedLedger(ctx context.Context, userID string) ([]domain.FeedLedgerEntry, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, ErrUnauthorized
	}
	if s.feed == nil {
		return nil, fmt.Errorf("feed contributions are not configured")
	}
	return s.feed.ListFeedLedger(ctx, userID)
}

func isoWeekStart(t time.Time) time.Time {
	t = t.UTC()
	daysSinceMonday := (int(t.Weekday()) + 6) % 7
	start := t.AddDate(0, 0, -daysSinceMonday)
	return time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.UTC)
}
