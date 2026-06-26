package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type ResendMailer struct {
	APIKey    string
	FromEmail string
}

func (m *ResendMailer) SendVerificationEmail(ctx context.Context, toEmail, verifyURL string) error {
	body := map[string]any{
		"from":    m.FromEmail,
		"to":      []string{toEmail},
		"subject": "Verify your Potpuri email address",
		"html": fmt.Sprintf(`<p>Thanks for signing up for Potpuri!</p>
<p>Click the link below to verify your email address:</p>
<p><a href="%s">Verify email address</a></p>
<p>This link expires in 48 hours. If you did not sign up for Potpuri, you can ignore this email.</p>`, verifyURL),
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("resend: HTTP %d", resp.StatusCode)
	}
	return nil
}
