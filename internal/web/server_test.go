package web_test

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"potpuri/internal/security"
	"potpuri/internal/storage/memory"
	"potpuri/internal/usecase"
	"potpuri/internal/web"
)

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
	token, err := svc.Login(context.Background(), user.Email, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
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
	token, err := svc.Login(context.Background(), user.Email, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
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
	token, err := svc.Login(context.Background(), user.Email, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	server := web.NewServer(svc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "potpuri_session", Value: token})
	server.Routes().ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `href="/add"`) {
		t.Fatalf("home page missing add link: %s", body)
	}
	if strings.Contains(body, `name="source_url"`) || strings.Contains(body, `type="file"`) {
		t.Fatalf("home page should not show capture form: %s", body)
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
	token, err := svc.Login(context.Background(), user.Email, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
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
	for _, want := range []string{"https://example.com/page", "# Markdown note", "receipt.txt", "ZmlsZSBjb250ZW50cw=="} {
		if !strings.Contains(items[0].Body+items[0].SourceURL, want) {
			t.Fatalf("combined entry missing %q: %#v", want, items[0])
		}
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
	token, err := svc.Login(context.Background(), user.Email, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
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
