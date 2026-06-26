package web_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	pquerna_totp "github.com/pquerna/otp/totp"

	"potpuri/internal/security"
	"potpuri/internal/storage/memory"
	"potpuri/internal/usecase"
	"potpuri/internal/web"
)

func mustLogin(t *testing.T, svc *usecase.Service, email, password string) string {
	t.Helper()
	result, err := svc.Login(context.Background(), email, password)
	if err != nil {
		t.Fatal(err)
	}
	return result.SessionToken
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestItemsAPIRequiresAuthentication(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/items", strings.NewReader(`{"title":"x"}`))
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rec.Code)
	}
}

func TestAuthenticatedUserCanCreateAndSearchThroughHTTP(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "web@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/items", strings.NewReader(`{"Type":"note","Title":"Saved link","Body":"karakeep linkwarden notes","Tags":["Links"]}`))
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/items?q=linkwarden", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("search failed: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Saved link") {
		t.Fatalf("search response did not include saved item: %s", rec.Body.String())
	}
}

func TestClipboardAPIInfersURLItem(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "clip@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/clipboard", strings.NewReader(`{"text":"https://example.com/article"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clipboard capture failed: %d %s", rec.Code, rec.Body.String())
	}
	items, err := svc.SearchItems(context.Background(), user.ID, "example")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one URL item, got %#v", items)
	}
	if items[0].Type != "url" || items[0].SourceURL != "https://example.com/article" {
		t.Fatalf("URL was not inferred: %#v", items[0])
	}
}

func TestClipboardAPIRejectsEmptyCapture(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "empty-clip@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/clipboard", strings.NewReader(`{"text":"   "}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected empty clipboard to be rejected, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "clipboard is empty") {
		t.Fatalf("expected useful empty clipboard error, got %q", rec.Body.String())
	}
}

func TestAddPageHasManualCaptureFormWithoutClipboardButton(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "add-page@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/add", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, want := range []string{`id="body"`, `id="files"`, `name="source_url"`, `>Add</button>`} {
		if !strings.Contains(body, want) {
			t.Fatalf("add page missing %s: %s", want, body)
		}
	}
	for _, removed := range []string{`Add clipboard`, `navigator.clipboard`, `clipboard-button`, `clipboard-status`, `Promise.race`} {
		if strings.Contains(body, removed) {
			t.Fatalf("add page still contains clipboard behavior %q: %s", removed, body)
		}
	}
}

func TestHomeShowsAddLinkAndNotCaptureForm(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "home@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `href="/add"`) {
		t.Fatalf("home page missing add link: %s", body)
	}
	for _, want := range []string{`href="/docs"`, `href="/tos"`, `href="/privacy"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("home page missing document link %s: %s", want, body)
		}
	}
	if !strings.Contains(body, `href="/static/rose.svg"`) || !strings.Contains(body, `src="/static/rose.svg"`) {
		t.Fatalf("home page missing rose logo/favicon: %s", body)
	}
	if !strings.Contains(body, `overflow-wrap:anywhere`) {
		t.Fatalf("home page stylesheet should wrap long text: %s", body)
	}
	for _, want := range []string{`id="entry-search"`, `addEventListener('input',filter)`, `position:sticky`, `background:#fff`} {
		if !strings.Contains(body, want) {
			t.Fatalf("home page missing client search hook %s: %s", want, body)
		}
	}
	if strings.Contains(body, `name="source_url"`) || strings.Contains(body, `type="file"`) {
		t.Fatalf("home page should not show capture form: %s", body)
	}
}

func TestSignedOutHomeShowsIntroAndSignInLink(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	server.Routes().ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, want := range []string{
		`class="signed-out"`,
		`src="/static/rose.svg"`,
		`<h1>Potpuri</h1>`,
		`Potpuri is a free, secure minimalistic digital treasue trove. You can save links, files, photos, and markdown notes for later. No tracking, no LLM bullshit.`,
		`href="/login">Sign in</a>`,
		`href="https://github.com/PAndreew/potpuri">GitHub</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("signed out home missing %s: %s", want, body)
		}
	}
	for _, removed := range []string{`action="/register"`, `action="/login"`, `<h2>Register</h2>`} {
		if strings.Contains(body, removed) {
			t.Fatalf("signed out home should not show auth form %q: %s", removed, body)
		}
	}
}

func TestDocumentPagesRender(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	server := web.NewServer(svc)

	for path, want := range map[string]string{
		"/docs":    "Docs",
		"/tos":     "Terms of Service",
		"/privacy": "Privacy Policy",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		server.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s failed: %d %s", path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("%s missing %q: %s", path, want, rec.Body.String())
		}
	}
}

func TestLoginPageShowsCenteredSignInFormWithSignUpLink(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	server.Routes().ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, want := range []string{`<title>Sign in - Potpuri</title>`, `class="auth-page"`, `class="auth-form"`, `class="auth-logo" src="/static/rose.svg"`, `flex-direction:column`, `padding:8px 16px`, `action="/login"`, `type="email"`, `type="password"`, `<button>Sign in</button>`, `class="signup-link" href="/register">Sign up</a>`} {
		if !strings.Contains(body, want) {
			t.Fatalf("login page missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, `action="/register"`) {
		t.Fatalf("login page should link to sign up rather than render the sign up form: %s", body)
	}
}

func TestAdminShowsSignedUpUsersAndPatronStatus(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "owner@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetPatron(context.Background(), user.ID, true); err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServerWithConfig(svc, web.Config{AdminEmail: "owner@example.com"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin page failed: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"owner@example.com", ">Patron<", "<th>Email</th>", "<th>Signed up</th>"} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin page missing %s: %s", want, body)
		}
	}
}

func TestAdminRejectsNonAdminUser(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "someone@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServerWithConfig(svc, web.Config{AdminEmail: "owner@example.com"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin should be forbidden, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestStripeWebhookSetsPatronFromCheckoutSession(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "stripe@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	server := web.NewServerWithConfig(svc, web.Config{
		StripeSecretKey:     "sk_test_x",
		StripePriceID:       "price_x",
		StripeWebhookSecret: "whsec_test",
	})
	body := `{"type":"checkout.session.completed","data":{"object":{"client_reference_id":"` + user.ID + `","metadata":{"user_id":"` + user.ID + `"}}}}`
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte("whsec_test"))
	_, _ = mac.Write([]byte(timestamp + "." + body))
	signature := "t=" + timestamp + ",v1=" + hex.EncodeToString(mac.Sum(nil))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(body))
	req.Header.Set("Stripe-Signature", signature)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("webhook failed: %d %s", rec.Code, rec.Body.String())
	}
	updated, err := svc.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Patron {
		t.Fatalf("expected Stripe webhook to set patron")
	}
}

func TestRegisterPageShowsCenteredSignUpForm(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	server.Routes().ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, want := range []string{`<title>Sign up - Potpuri</title>`, `class="auth-page"`, `class="auth-form"`, `class="auth-logo" src="/static/rose.svg"`, `action="/register"`, `type="email"`, `type="password"`, `<button>Sign up</button>`} {
		if !strings.Contains(body, want) {
			t.Fatalf("register page missing %s: %s", want, body)
		}
	}
}

func TestRegistrationCanBeClosed(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	server := web.NewServerWithConfig(svc, web.Config{AllowRegistration: false})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("closed registration GET should be forbidden, got %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/login", nil)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login page should still load when registration is closed: %d", rec.Code)
	}
}

func TestSecureCookieSettingsCanBeEnabled(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	if _, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "cookie@example.com", Password: "correct horse"}); err != nil {
		t.Fatal(err)
	}
	server := web.NewServerWithConfig(svc, web.Config{AllowRegistration: false, SecureCookies: true})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("email=cookie%40example.com&password=correct+horse"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %#v", cookies)
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie should be HttpOnly, Secure, SameSite Strict: %#v", cookie)
	}
}

func TestHomeShowsEditActionAndGhostDeleteButton(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "actions@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	item, err := svc.CreateItem(context.Background(), usecase.CreateItemInput{UserID: user.ID, Title: "Action item", Body: "edit me"})
	if err != nil {
		t.Fatal(err)
	}
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, want := range []string{`<button class="plain">Log out</button>`, `href="/items/edit?id=` + item.ID + `"`, `class="button"`, `class="ghost"`, `class="danger-text"`, `data-search=`, `Action item`, `edit me`} {
		if !strings.Contains(body, want) {
			t.Fatalf("home page missing item action %s: %s", want, body)
		}
	}
}

func TestHomeRendersUploadedImageBlocksAsRoundedImages(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "image@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	body := "# Heading\n\n**bold** [evil](javascript:alert(1)) <script>alert(1)</script>\n\n## Uploaded files\n\n### photo.png\n\nContent-Type: image/png\nSize: 3 bytes\n\n```base64\nAQID\n```"
	if _, err := svc.CreateItem(context.Background(), usecase.CreateItemInput{UserID: user.ID, Title: "Photo", Body: body}); err != nil {
		t.Fatal(err)
	}
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	page := rec.Body.String()
	// The uploaded image still renders as a rounded figure, and the editable
	// text above it is now rendered as Markdown.
	for _, want := range []string{`class="uploaded-image"`, `border-radius:12px`, `src="data:image/png;base64,AQID"`, `alt="photo.png"`, `<figcaption>photo.png</figcaption>`, `<h1>Heading</h1>`, `<strong>bold</strong>`} {
		if !strings.Contains(page, want) {
			t.Fatalf("home page missing rendered detail %s: %s", want, page)
		}
	}
	// Markdown rendering must not become an injection surface: raw <script>,
	// javascript: links, and the raw base64 upload block stay out of the page.
	for _, removed := range []string{`<script>alert(1)</script>`, `href="javascript:`, "```base64\nAQID\n```"} {
		if strings.Contains(page, removed) {
			t.Fatalf("home page should not expose unsafe body fragment %q: %s", removed, page)
		}
	}
}

func TestHomeRendersBlobBackedImageUploads(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "blob-image@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServer(svc)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("title", "Photo")
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", `form-data; name="files"; filename="photo.png"`)
	header.Set("Content-Type", "image/png")
	part, err := writer.CreatePart(header)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte{1, 2, 3})
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/items", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create failed: %d %s", rec.Code, rec.Body.String())
	}
	items, err := svc.ListItems(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(items[0].Blobs) != 1 {
		t.Fatalf("expected one item with one blob, got %#v", items)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	page := rec.Body.String()
	if !strings.Contains(page, `class="uploaded-image"`) || !strings.Contains(page, `/items/blob?id=`+items[0].Blobs[0].ID) || strings.Contains(page, "```base64") {
		t.Fatalf("home page did not render blob-backed image: %s", page)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/items/blob?id="+items[0].Blobs[0].ID, nil)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("blob route should require auth, got %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/items/blob?id="+items[0].Blobs[0].ID, nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != string([]byte{1, 2, 3}) {
		t.Fatalf("blob route did not return content: %d %q", rec.Code, rec.Body.String())
	}
}

func TestRoseLogoIsServedAsSVG(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/rose.svg", nil)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected logo to be served, got %d", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "image/svg+xml") {
		t.Fatalf("expected SVG content type, got %q", contentType)
	}
	if !strings.Contains(rec.Body.String(), "<svg") {
		t.Fatalf("expected SVG body, got %s", rec.Body.String())
	}
}

func TestHTMLCreateCombinesURLNoteAndFileIntoOneEntry(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "upload@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServer(svc)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("title", "One capture")
	_ = writer.WriteField("source_url", "https://example.com/page")
	_ = writer.WriteField("body", "# Markdown note\nwith context")
	part, err := writer.CreateFormFile("files", "receipt.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("file contents"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/items", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create failed: %d %s", rec.Code, rec.Body.String())
	}

	items, err := svc.SearchItems(context.Background(), user.ID, "receipt")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one combined entry, got %#v", items)
	}
	if items[0].Type != "file" {
		t.Fatalf("expected file item type, got %s", items[0].Type)
	}
	for _, want := range []string{"https://example.com/page", "# Markdown note"} {
		if !strings.Contains(items[0].Body+items[0].SourceURL, want) {
			t.Fatalf("combined entry missing %q: %#v", want, items[0])
		}
	}
	if strings.Contains(items[0].Body, "ZmlsZSBjb250ZW50cw==") {
		t.Fatalf("uploaded file should not be inlined as base64: %#v", items[0])
	}
	if len(items[0].Blobs) != 1 || items[0].Blobs[0].Filename != "receipt.txt" {
		t.Fatalf("expected uploaded file blob metadata, got %#v", items[0].Blobs)
	}
	blob, content, err := svc.GetBlob(context.Background(), user.ID, items[0].Blobs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if blob.Filename != "receipt.txt" || string(content) != "file contents" {
		t.Fatalf("uploaded blob was not retrievable: %#v %q", blob, string(content))
	}

	var editBody bytes.Buffer
	editWriter := multipart.NewWriter(&editBody)
	_ = editWriter.WriteField("id", items[0].ID)
	_ = editWriter.WriteField("title", "Updated capture")
	_ = editWriter.WriteField("body", "updated note")
	if err := editWriter.Close(); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/items/edit", &editBody)
	req.Header.Set("Content-Type", editWriter.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("edit failed: %d %s", rec.Code, rec.Body.String())
	}
	items, err = svc.SearchItems(context.Background(), user.ID, "receipt")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Type != "file" || len(items[0].Blobs) != 1 {
		t.Fatalf("edit should preserve file type, blob metadata, and filename search: %#v", items)
	}
}

func TestAuthenticatedUserCanEditItemThroughHTML(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "edit@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	item, err := svc.CreateItem(context.Background(), usecase.CreateItemInput{UserID: user.ID, Title: "Draft", Body: "old body", Tags: []string{"old"}})
	if err != nil {
		t.Fatal(err)
	}
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/items/edit?id="+item.ID, nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("edit form failed: %d %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{`value="Draft"`, `old body`, `value="old"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("edit form missing %s: %s", want, rec.Body.String())
		}
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("id", item.ID)
	_ = writer.WriteField("title", "Published")
	_ = writer.WriteField("source_url", "https://example.com/edited")
	_ = writer.WriteField("body", "new body")
	_ = writer.WriteField("tags", "edited, notes")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/items/edit", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("edit failed: %d %s", rec.Code, rec.Body.String())
	}
	updated, err := svc.GetItem(context.Background(), user.ID, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Title != "Published" || updated.Body != "new body" || updated.SourceURL != "https://example.com/edited" {
		t.Fatalf("item was not updated: %#v", updated)
	}
	if strings.Join(updated.Tags, ",") != "edited,notes" {
		t.Fatalf("tags were not updated: %#v", updated.Tags)
	}
}

func TestEditPageKeepsUploadedImagesOutOfTextareaAndPreservesThemOnSave(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "edit-image@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	itemBody := "## Uploaded files\n\n### photo.png\n\nContent-Type: image/png\nSize: 3 bytes\n\n```base64\nAQID\n```"
	item, err := svc.CreateItem(context.Background(), usecase.CreateItemInput{UserID: user.ID, Title: "Photo", Body: itemBody})
	if err != nil {
		t.Fatal(err)
	}
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/items/edit?id="+item.ID, nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("edit form failed: %d %s", rec.Code, rec.Body.String())
	}
	editPage := rec.Body.String()
	if !strings.Contains(editPage, `<textarea id="body" name="body" rows="10" placeholder="Paste or write anything"></textarea>`) {
		t.Fatalf("edit textarea should contain only editable text: %s", editPage)
	}
	if strings.Contains(editPage, "```base64") {
		t.Fatalf("edit page should not expose uploaded image base64: %s", editPage)
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("id", item.ID)
	_ = writer.WriteField("title", "Photo")
	_ = writer.WriteField("body", "updated caption")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/items/edit", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("edit failed: %d %s", rec.Code, rec.Body.String())
	}
	updated, err := svc.GetItem(context.Background(), user.ID, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(updated.Body, "updated caption") || !strings.Contains(updated.Body, "AQID") {
		t.Fatalf("edit should preserve text changes and uploaded image: %#v", updated.Body)
	}
}

func TestAuthenticatedUserCanDeleteItemThroughHTML(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "delete@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	item, err := svc.CreateItem(context.Background(), usecase.CreateItemInput{UserID: user.ID, Title: "Temporary", Body: "delete route"})
	if err != nil {
		t.Fatal(err)
	}
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/items/delete", strings.NewReader("id="+item.ID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete failed: %d %s", rec.Code, rec.Body.String())
	}
	items, err := svc.ListItems(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("expected item to be deleted, got %#v", items)
	}
}

func TestAPITokenAuthorizesClipboardAndItems(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "pat@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.CreateAPIToken(context.Background(), usecase.CreateAPITokenInput{UserID: user.ID, Name: "test token"})
	if err != nil {
		t.Fatal(err)
	}
	server := web.NewServer(svc)

	// Bearer token on /api/clipboard
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/clipboard", strings.NewReader(`{"title":"PAT test","text":"hello from token","url":"https://example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+result.RawToken)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clipboard with PAT failed: %d %s", rec.Code, rec.Body.String())
	}

	// Bearer token on /api/items search
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/items?q=hello", nil)
	req.Header.Set("Authorization", "Bearer "+result.RawToken)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("items search with PAT failed: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PAT test") {
		t.Fatalf("search result missing saved item: %s", rec.Body.String())
	}

	// Wrong token is rejected
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/clipboard", strings.NewReader(`{"text":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrongtoken")
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong PAT, got %d", rec.Code)
	}

	// CORS preflight gets 204
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodOptions, "/api/clipboard", nil)
	req.Header.Set("Origin", "https://other-site.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for OPTIONS preflight, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("expected CORS allow-origin *, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestShortcutAPISavesSharedURLWithFormToken(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "shortcut@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.CreateAPIToken(context.Background(), usecase.CreateAPITokenInput{UserID: user.ID, Name: "iOS Shortcut"})
	if err != nil {
		t.Fatal(err)
	}
	server := web.NewServer(svc)

	form := url.Values{}
	form.Set("token", result.RawToken)
	form.Set("title", "Shared Article")
	form.Set("url", "https://example.com/shared")
	form.Set("text", "Worth keeping")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/shortcut", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("shortcut save failed: %d %s", rec.Code, rec.Body.String())
	}
	items, err := svc.ListItems(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one shortcut item, got %d", len(items))
	}
	if items[0].Title != "Shared Article" || items[0].SourceURL != "https://example.com/shared" || items[0].Body != "Worth keeping" {
		t.Fatalf("shortcut item has wrong fields: %#v", items[0])
	}
	if !containsString(items[0].Tags, "shortcut") {
		t.Fatalf("shortcut item missing shortcut tag: %#v", items[0].Tags)
	}
}

func TestShortcutAPIRejectsMissingOrInvalidToken(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	server := web.NewServer(svc)

	for _, body := range []string{"text=hello", "token=wrong&text=hello"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/shortcut", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		server.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for %q, got %d", body, rec.Code)
		}
	}
}

func TestTokensPageShowsIOSShortcutRecipeForNewToken(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "shortcut-page@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	session := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tokens?new_token=pt_testtoken&new_name=iOS+Shortcut", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: session})
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected tokens page, got %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"iOS Shortcut", "/api/shortcut", "Show in Share Sheet", "Receive", "Get Contents of URL", "Share with Apps", "Run JavaScript on Webpage", "token = pt_testtoken"} {
		if !strings.Contains(body, want) {
			t.Fatalf("tokens page missing %q: %s", want, body)
		}
	}
}

func TestShareTargetSavesPageAndRedirectsHome(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "share@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/share?title=Great+Article&url=https%3A%2F%2Fexample.com%2Farticle&text=Interesting+read", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "/" {
		t.Fatalf("expected redirect to /, got %s", rec.Header().Get("Location"))
	}
	items, err := svc.ListItems(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one saved item, got %d", len(items))
	}
	if items[0].Title != "Great Article" || items[0].SourceURL != "https://example.com/article" {
		t.Fatalf("shared item has wrong fields: %#v", items[0])
	}
}

func TestShareTargetRequiresSessionCookie(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/share?title=x&url=https://example.com", nil)
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect to login, got %d", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("Location"), "/login") {
		t.Fatalf("expected redirect to /login, got %s", rec.Header().Get("Location"))
	}
}

func TestShareTargetWithNoContentRedirectsHome(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "share-empty@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/share", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	items, err := svc.ListItems(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("expected no items saved for empty share, got %d", len(items))
	}
}

func TestManifestIncludesShareTarget(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/manifest.webmanifest", nil)
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected manifest, got %d", rec.Code)
	}
	var m struct {
		ShareTarget struct {
			Action string `json:"action"`
			Method string `json:"method"`
			Params struct {
				Title string `json:"title"`
				Text  string `json:"text"`
				URL   string `json:"url"`
			} `json:"params"`
		} `json:"share_target"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&m); err != nil {
		t.Fatalf("manifest is not valid JSON: %v", err)
	}
	if m.ShareTarget.Action != "/share" {
		t.Fatalf("share_target.action expected /share, got %q", m.ShareTarget.Action)
	}
	if m.ShareTarget.Method != "GET" {
		t.Fatalf("share_target.method expected GET, got %q", m.ShareTarget.Method)
	}
	if m.ShareTarget.Params.Title != "title" || m.ShareTarget.Params.Text != "text" || m.ShareTarget.Params.URL != "url" {
		t.Fatalf("share_target.params wrong: %+v", m.ShareTarget.Params)
	}
}

func TestAccountPageShowsEmailAndExportLinks(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "account@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"account@example.com", `href="/export"`, `href="/export?format=bookmarks"`, `action="/account/delete"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("account page missing %s: %s", want, body)
		}
	}
}

func TestExportJSONContainsAllItems(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "export@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	if _, err := svc.CreateItem(context.Background(), usecase.CreateItemInput{UserID: user.ID, Title: "Exported Note", Body: "hello"}); err != nil {
		t.Fatal(err)
	}
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/export", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("expected JSON content type, got %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("expected attachment, got %q", cd)
	}
	if !strings.Contains(rec.Body.String(), "Exported Note") {
		t.Fatalf("export missing item: %s", rec.Body.String())
	}
}

func TestExportRequiresAuthentication(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/export", nil)
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestExportBookmarksContainsURLItems(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "bmarks@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	if _, err := svc.CreateItem(context.Background(), usecase.CreateItemInput{UserID: user.ID, Title: "Go Blog", SourceURL: "https://go.dev/blog"}); err != nil {
		t.Fatal(err)
	}
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/export?format=bookmarks", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "NETSCAPE-Bookmark-file-1") {
		t.Fatalf("bookmarks missing DOCTYPE: %s", body)
	}
	if !strings.Contains(body, "https://go.dev/blog") {
		t.Fatalf("bookmarks missing URL: %s", body)
	}
	if !strings.Contains(body, "Go Blog") {
		t.Fatalf("bookmarks missing title: %s", body)
	}
}

func TestDeleteAccountWithCorrectPasswordRemovesUser(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "deleteacct@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/account/delete", strings.NewReader("password=correct+horse"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.Login(context.Background(), user.Email, "correct horse"); err == nil {
		t.Fatal("expected login to fail after account deletion")
	}
}

func TestDeleteAccountWithWrongPasswordFails(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "wrongpwd@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	token := mustLogin(t, svc, user.Email, "correct horse")
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/account/delete", strings.NewReader("password=wrongpassword"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.Login(context.Background(), user.Email, "correct horse"); err != nil {
		t.Fatalf("user should still exist after failed deletion: %v", err)
	}
}

func TestDeleteAccountRequiresAuthentication(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/account/delete", strings.NewReader("password=whatever"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("Location"), "/login") {
		t.Fatalf("expected redirect to /login, got %s", rec.Header().Get("Location"))
	}
}

func TestLoginWith2FAEnabledRedirectsToTOTPPage(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "totp2fa@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := svc.SetupTOTP(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	code, err := pquerna_totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConfirmTOTP(context.Background(), user.ID, secret, code); err != nil {
		t.Fatal(err)
	}
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("email=totp2fa%40example.com&password=correct+horse"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "/login/totp" {
		t.Fatalf("expected redirect to /login/totp, got %s", rec.Header().Get("Location"))
	}
	var hasPreauth bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "potpuri_preauth" && c.Value != "" {
			hasPreauth = true
		}
	}
	if !hasPreauth {
		t.Fatal("expected potpuri_preauth cookie to be set")
	}
}

func TestTOTPLoginPageRequiresPreauthCookie(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login/totp", nil)
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("Location"), "/login") {
		t.Fatalf("expected redirect to /login, got %s", rec.Header().Get("Location"))
	}
}

func TestCompleteLoginWithValidTOTPCode(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "totpcode@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := svc.SetupTOTP(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	setupCode, err := pquerna_totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConfirmTOTP(context.Background(), user.ID, secret, setupCode); err != nil {
		t.Fatal(err)
	}
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("email=totpcode%40example.com&password=correct+horse"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login/totp" {
		t.Fatalf("expected redirect to /login/totp, got %d %s", rec.Code, rec.Header().Get("Location"))
	}
	var preauthCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "potpuri_preauth" {
			preauthCookie = c
		}
	}
	if preauthCookie == nil {
		t.Fatal("no preauth cookie set")
	}

	verifyCode, err := pquerna_totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/login/totp", strings.NewReader("code="+verifyCode))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(preauthCookie)
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("expected redirect to /, got %d %s", rec.Code, rec.Header().Get("Location"))
	}
	var hasSession bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "potpuri_session" && c.Value != "" {
			hasSession = true
		}
	}
	if !hasSession {
		t.Fatal("expected session cookie after TOTP verification")
	}
}

func TestTOTPSetupConfirmAndDisableFlow(t *testing.T) {
	store := memory.New()
	cipher, err := security.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	svc := usecase.NewService(usecase.NewServiceParams{Users: store, Items: store, Sessions: store, Cipher: cipher, Hasher: security.NewPasswordHasher()})
	user, err := svc.Register(context.Background(), usecase.RegisterInput{Email: "totpflow@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}

	_, secret, err := svc.SetupTOTP(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("SetupTOTP failed: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}

	code, err := pquerna_totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recoveryCodes, err := svc.ConfirmTOTP(context.Background(), user.ID, secret, code)
	if err != nil {
		t.Fatalf("ConfirmTOTP failed: %v", err)
	}
	if len(recoveryCodes) == 0 {
		t.Fatal("expected recovery codes")
	}

	u, err := svc.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !u.TOTPEnabled {
		t.Fatal("expected TOTP to be enabled")
	}

	disableCode, err := pquerna_totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DisableTOTP(context.Background(), user.ID, disableCode); err != nil {
		t.Fatalf("DisableTOTP failed: %v", err)
	}
	u, err = svc.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if u.TOTPEnabled {
		t.Fatal("expected TOTP to be disabled after DisableTOTP")
	}
}
