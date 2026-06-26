package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/microcosm-cc/bluemonday"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	goldmarkhtml "github.com/yuin/goldmark/renderer/html"

	"potpuri/internal/domain"
	"potpuri/internal/usecase"
)

//go:embed static/rose.svg
var roseSVG []byte

//go:embed templates/*.html
var templatesFS embed.FS

var templateFuncs = template.FuncMap{
	"renderBody":      renderBody,
	"isImageBlob":     isImageBlob,
	"blobURL":         blobURL,
	"blobDownloadURL": blobDownloadURL,
	"joinTags":        joinTags,
	"snippet":         snippet,
	"fmtDate":         fmtDate,
	"editableText":    editableText,
}

func editableText(body string) string {
	text, _ := splitUploadedFiles(body)
	return text
}

type Server struct {
	svc             *usecase.Service
	index           *template.Template
	loginTpl        *template.Template
	loginTOTPTpl    *template.Template
	registerTpl     *template.Template
	addTpl          *template.Template
	editTpl         *template.Template
	tokensTpl       *template.Template
	accountTpl      *template.Template
	totpConfirmTpl  *template.Template
	totpRecoveryTpl *template.Template
	patronTpl       *template.Template
	adminTpl        *template.Template
	docsTpl         *template.Template
	tosTpl          *template.Template
	privacyTpl      *template.Template
	config          Config
}

type Config struct {
	AllowRegistration   bool
	SecureCookies       bool
	AdminEmail          string
	StripeSecretKey     string
	StripePriceID       string
	StripeWebhookSecret string
	PublicURL           string
}

func NewServer(svc *usecase.Service) *Server {
	return NewServerWithConfig(svc, Config{AllowRegistration: true})
}

func NewServerWithConfig(svc *usecase.Service, config Config) *Server {
	return &Server{
		svc:             svc,
		index:           parsePage("index.html"),
		loginTpl:        parsePage("login.html"),
		registerTpl:     parsePage("register.html"),
		addTpl:          parsePage("add.html"),
		editTpl:         parsePage("edit.html"),
		tokensTpl:       parsePage("tokens.html"),
		accountTpl:      parsePage("account.html"),
		totpConfirmTpl:  parsePage("totp_confirm.html"),
		totpRecoveryTpl: parsePage("totp_recovery.html"),
		loginTOTPTpl:    parsePage("login_totp.html"),
		patronTpl:       parsePage("patron.html"),
		adminTpl:        parsePage("admin.html"),
		docsTpl:         parsePage("docs.html"),
		tosTpl:          parsePage("tos.html"),
		privacyTpl:      parsePage("privacy.html"),
		config:          config,
	}
}

// parsePage builds a standalone template set for one page: the shared base
// layout, styles, and header partials plus the page-specific body. Each page
// gets its own set so the per-page "title"/"body" definitions do not collide.
func parsePage(page string) *template.Template {
	return template.Must(template.New("base").Funcs(templateFuncs).ParseFS(
		templatesFS,
		"templates/base.html",
		"templates/styles.html",
		"templates/header.html",
		"templates/"+page,
	))
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.home)
	mux.HandleFunc("/add", s.add)
	mux.HandleFunc("/register", s.register)
	mux.HandleFunc("/login", s.login)
	mux.HandleFunc("/logout", s.logout)
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/login/totp", s.loginTOTPHTML)
	mux.HandleFunc("/account/2fa/setup", s.setup2faHTML)
	mux.HandleFunc("/account/2fa/confirm", s.confirm2faHTML)
	mux.HandleFunc("/account/2fa/disable", s.disable2faHTML)
	mux.HandleFunc("/patron", s.patronHTML)
	mux.HandleFunc("/billing/checkout", s.checkoutHTML)
	mux.HandleFunc("/stripe/webhook", s.stripeWebhook)
	mux.HandleFunc("/admin", s.adminHTML)
	mux.HandleFunc("/docs", s.docsHTML)
	mux.HandleFunc("/tos", s.tosHTML)
	mux.HandleFunc("/privacy", s.privacyHTML)
	mux.HandleFunc("/share", s.shareHTML)
	mux.HandleFunc("/account", s.accountHTML)
	mux.HandleFunc("/account/delete", s.deleteAccountHTML)
	mux.HandleFunc("/export", s.exportHandler)
	mux.HandleFunc("/tokens", s.tokensHTML)
	mux.HandleFunc("/tokens/revoke", s.revokeTokenHTML)
	mux.HandleFunc("/items", s.createItemHTML)
	mux.HandleFunc("/items/edit", s.editItemHTML)
	mux.HandleFunc("/items/delete", s.deleteItemHTML)
	mux.HandleFunc("/items/blob", s.blobHTML)
	mux.HandleFunc("/api/items", corsAPI(s.itemsAPI))
	mux.HandleFunc("/api/clipboard", corsAPI(s.clipboardAPI))
	mux.HandleFunc("/api/shortcut", corsAPI(s.shortcutAPI))
	mux.HandleFunc("/manifest.webmanifest", manifest)
	mux.HandleFunc("/sw.js", serviceWorker)
	mux.HandleFunc("/static/rose.svg", roseLogo)
	return mux
}

// corsAPI wraps an API handler with permissive CORS headers so bookmarklets
// and external tools can call the API with a Bearer token from any origin.
func corsAPI(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

func health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	userID, _ := s.currentUserID(r)
	var items []domain.Item
	if userID != "" {
		query := r.URL.Query().Get("q")
		var err error
		if query == "" {
			items, err = s.svc.ListItems(r.Context(), userID)
		} else {
			items, err = s.svc.SearchItems(r.Context(), userID, query)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	_ = s.index.Execute(w, map[string]any{"UserID": userID, "Items": items, "Query": r.URL.Query().Get("q")})
}

func (s *Server) add(w http.ResponseWriter, r *http.Request) {
	userID, _ := s.currentUserID(r)
	if userID == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_ = s.addTpl.Execute(w, map[string]any{"UserID": userID})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.config.AllowRegistration {
		http.Error(w, "registration is closed", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		_ = s.registerTpl.Execute(w, nil)
		return
	}
	user, err := s.svc.Register(r.Context(), usecase.RegisterInput{Email: r.FormValue("email"), Password: r.FormValue("password")})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, err := s.svc.Login(r.Context(), user.Email, r.FormValue("password"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	s.setSession(w, result.SessionToken)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		_ = s.loginTpl.Execute(w, map[string]any{"AllowRegistration": s.config.AllowRegistration})
		return
	}
	result, err := s.svc.Login(r.Context(), r.FormValue("email"), r.FormValue("password"))
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if result.RequiresTOTP {
		http.SetCookie(w, &http.Cookie{
			Name:     "potpuri_preauth",
			Value:    result.PreauthToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   s.config.SecureCookies,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   300,
		})
		http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
		return
	}
	s.setSession(w, result.SessionToken)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "potpuri_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.config.SecureCookies, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) createItemHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	input, err := itemInputFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	input.UserID = userID
	_, err = s.svc.CreateItem(r.Context(), input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) editItemHTML(w http.ResponseWriter, r *http.Request) {
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		item, err := s.svc.GetItem(r.Context(), userID, r.URL.Query().Get("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		editableBody, _ := splitUploadedFiles(item.Body)
		_ = s.editTpl.Execute(w, map[string]any{"UserID": userID, "Item": item, "EditableBody": editableBody})
	case http.MethodPost:
		input, err := itemInputFromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		existing, err := s.svc.GetItem(r.Context(), userID, r.FormValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if len(input.Blobs) == 0 {
			input.Type = existing.Type
		}
		_, existingUploads := splitUploadedFiles(existing.Body)
		input.Body = appendUploadedFiles(input.Body, existingUploads)
		_, err = s.svc.UpdateItem(r.Context(), usecase.UpdateItemInput{
			ID:        r.FormValue("id"),
			UserID:    userID,
			Type:      input.Type,
			Title:     input.Title,
			Body:      input.Body,
			SourceURL: input.SourceURL,
			Tags:      input.Tags,
			Blobs:     input.Blobs,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) deleteItemHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	if err := s.svc.DeleteItem(r.Context(), userID, r.FormValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) blobHTML(w http.ResponseWriter, r *http.Request) {
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	blob, content, err := s.svc.GetBlob(r.Context(), userID, r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if r.URL.Query().Get("download") == "1" {
		safe := strings.ReplaceAll(blob.Filename, `"`, "_")
		w.Header().Set("Content-Disposition", `attachment; filename="`+safe+`"`)
	}
	w.Header().Set("Content-Type", blob.ContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(content)
}

func (s *Server) itemsAPI(w http.ResponseWriter, r *http.Request) {
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := s.svc.SearchItems(r.Context(), userID, r.URL.Query().Get("q"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, items)
	case http.MethodPost:
		var input usecase.CreateItemInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		input.UserID = userID
		item, err := s.svc.CreateItem(r.Context(), input)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, item)
	case http.MethodDelete:
		itemID := strings.TrimPrefix(r.URL.Path, "/api/items/")
		if itemID == "" || itemID == r.URL.Path {
			itemID = r.URL.Query().Get("id")
		}
		if err := s.svc.DeleteItem(r.Context(), userID, itemID); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) clipboardAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	var itemInput usecase.CreateItemInput
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		var err error
		itemInput, err = itemInputFromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		itemInput.Tags = append(itemInput.Tags, "clipboard")
	} else {
		var input struct {
			Text   string `json:"text"`
			Title  string `json:"title"`
			URL    string `json:"url"`
			Source string `json:"source"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		itemInput = itemInputFromClipboardText(input.Text, input.Title, firstNonEmpty(input.URL, input.Source))
	}
	if !hasCaptureContent(itemInput) {
		http.Error(w, "clipboard is empty or unavailable", http.StatusBadRequest)
		return
	}
	itemInput.UserID = userID
	item, err := s.svc.CreateItem(r.Context(), itemInput)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, item)
}

func (s *Server) shortcutAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.FormValue("token"))
	if token == "" {
		http.Error(w, "token is required", http.StatusUnauthorized)
		return
	}
	userID, err := s.svc.UserIDForAPIToken(r.Context(), token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	itemInput := itemInputFromClipboardText(r.FormValue("text"), r.FormValue("title"), firstNonEmpty(r.FormValue("url"), r.FormValue("source")))
	if !hasCaptureContent(itemInput) {
		http.Error(w, "shortcut input is empty", http.StatusBadRequest)
		return
	}
	itemInput.UserID = userID
	itemInput.Tags = append(itemInput.Tags, "shortcut")
	item, err := s.svc.CreateItem(r.Context(), itemInput)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, item)
}

func (s *Server) currentUserID(r *http.Request) (string, error) {
	if cookie, err := r.Cookie("potpuri_session"); err == nil {
		if userID, err := s.svc.UserIDForSession(r.Context(), cookie.Value); err == nil {
			return userID, nil
		}
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return s.svc.UserIDForAPIToken(r.Context(), strings.TrimPrefix(auth, "Bearer "))
	}
	return "", errors.New("not authenticated")
}

func (s *Server) accountHTML(w http.ResponseWriter, r *http.Request) {
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	user, err := s.svc.GetUser(r.Context(), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.accountTpl.Execute(w, map[string]any{
		"UserID":      userID,
		"Email":       user.Email,
		"TOTPEnabled": user.TOTPEnabled,
		"Patron":      user.Patron,
	})
}

func (s *Server) loginTOTPHTML(w http.ResponseWriter, r *http.Request) {
	preauthCookie, err := r.Cookie("potpuri_preauth")
	if err != nil || preauthCookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		_ = s.loginTOTPTpl.Execute(w, nil)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	sessionToken, err := s.svc.CompleteLoginTOTP(r.Context(), preauthCookie.Value, r.FormValue("code"))
	if err != nil {
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "potpuri_preauth", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	s.setSession(w, sessionToken)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) setup2faHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	_, _, err = s.svc.SetupTOTP(r.Context(), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/account/2fa/confirm", http.StatusSeeOther)
}

func (s *Server) confirm2faHTML(w http.ResponseWriter, r *http.Request) {
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		user, err := s.svc.GetUser(r.Context(), userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		uri, secret, err := s.svc.SetupTOTP(r.Context(), userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = user
		png, err := qrcode.Encode(uri, qrcode.Medium, 200)
		var qrDataURL string
		if err == nil {
			qrDataURL = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
		}
		_ = s.totpConfirmTpl.Execute(w, map[string]any{
			"UserID":    userID,
			"Secret":    secret,
			"QRDataURL": qrDataURL,
		})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	codes, err := s.svc.ConfirmTOTP(r.Context(), userID, r.FormValue("secret"), r.FormValue("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = s.totpRecoveryTpl.Execute(w, map[string]any{"UserID": userID, "Codes": codes})
}

func (s *Server) disable2faHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := s.svc.DisableTOTP(r.Context(), userID, r.FormValue("code")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (s *Server) deleteAccountHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := s.svc.DeleteAccount(r.Context(), userID, r.FormValue("password")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "potpuri_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.config.SecureCookies, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) exportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	items, err := s.svc.ListItems(r.Context(), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if r.URL.Query().Get("format") == "bookmarks" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="potpuri-bookmarks.html"`)
		writeNetscapeBookmarks(w, items)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="potpuri-export.json"`)
	_ = json.NewEncoder(w).Encode(items)
}

func writeNetscapeBookmarks(w io.Writer, items []domain.Item) {
	fmt.Fprintln(w, `<!DOCTYPE NETSCAPE-Bookmark-file-1>`)
	fmt.Fprintln(w, `<!-- This is an automatically generated file. -->`)
	fmt.Fprintln(w, `<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">`)
	fmt.Fprintln(w, `<TITLE>Bookmarks</TITLE>`)
	fmt.Fprintln(w, `<H1>Bookmarks from Potpuri</H1>`)
	fmt.Fprintln(w, `<DL><p>`)
	for _, item := range items {
		if item.SourceURL == "" {
			continue
		}
		fmt.Fprintf(w, "    <DT><A HREF=%q ADD_DATE=%q>%s</A>\n",
			item.SourceURL,
			fmt.Sprintf("%d", item.CreatedAt.Unix()),
			template.HTMLEscapeString(item.Title))
	}
	fmt.Fprintln(w, `</DL><p>`)
}

func (s *Server) patronHTML(w http.ResponseWriter, r *http.Request) {
	userID, _ := s.currentUserID(r)
	var patron bool
	if userID != "" {
		if user, err := s.svc.GetUser(r.Context(), userID); err == nil {
			patron = user.Patron
		}
	}
	_ = s.patronTpl.Execute(w, map[string]any{
		"UserID":           userID,
		"Patron":           patron,
		"StripeConfigured": s.stripeConfigured(),
	})
}

func (s *Server) checkoutHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/patron", http.StatusSeeOther)
		return
	}
	if !s.stripeConfigured() {
		http.Error(w, "Stripe is not configured", http.StatusServiceUnavailable)
		return
	}
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	user, err := s.svc.GetUser(r.Context(), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	checkoutURL, err := s.createStripeCheckoutSession(r, user.ID, user.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, checkoutURL, http.StatusSeeOther)
}

func (s *Server) adminHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}
	users, err := s.svc.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{}
	data["Users"] = users
	_ = s.adminTpl.Execute(w, data)
}

func (s *Server) docsHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	userID, _ := s.currentUserID(r)
	_ = s.docsTpl.Execute(w, map[string]any{"UserID": userID})
}

func (s *Server) tosHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	userID, _ := s.currentUserID(r)
	_ = s.tosTpl.Execute(w, map[string]any{"UserID": userID})
}

func (s *Server) privacyHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	userID, _ := s.currentUserID(r)
	_ = s.privacyTpl.Execute(w, map[string]any{"UserID": userID})
}

func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	adminEmail := strings.TrimSpace(strings.ToLower(s.config.AdminEmail))
	if adminEmail == "" {
		http.Error(w, "admin email is not configured", http.StatusServiceUnavailable)
		return false
	}
	cookie, err := r.Cookie("potpuri_session")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return false
	}
	userID, err := s.svc.UserIDForSession(r.Context(), cookie.Value)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return false
	}
	user, err := s.svc.GetUser(r.Context(), userID)
	if err != nil {
		http.Error(w, "admin access denied", http.StatusForbidden)
		return false
	}
	if strings.TrimSpace(strings.ToLower(user.Email)) != adminEmail {
		http.Error(w, "admin access denied", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) shareHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	q := r.URL.Query()
	input := itemInputFromClipboardText(q.Get("text"), q.Get("title"), q.Get("url"))
	if !hasCaptureContent(input) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	input.UserID = userID
	if _, err := s.svc.CreateItem(r.Context(), input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) tokensHTML(w http.ResponseWriter, r *http.Request) {
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	switch r.Method {
	case http.MethodGet:
		tokens, err := s.svc.ListAPITokens(r.Context(), userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		scheme := "https"
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			scheme = "http"
		}
		baseURL := scheme + "://" + r.Host
		data := map[string]any{
			"UserID":   userID,
			"Tokens":   tokens,
			"BaseURL":  baseURL,
			"NewToken": r.URL.Query().Get("new_token"),
			"NewName":  r.URL.Query().Get("new_name"),
		}
		_ = s.tokensTpl.Execute(w, data)
	case http.MethodPost:
		result, err := s.svc.CreateAPIToken(r.Context(), usecase.CreateAPITokenInput{
			UserID: userID,
			Name:   r.FormValue("name"),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/tokens?new_token="+template.URLQueryEscaper(result.RawToken)+"&new_name="+template.URLQueryEscaper(result.Token.Name), http.StatusSeeOther)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) revokeTokenHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tokens", http.StatusSeeOther)
		return
	}
	userID, err := s.currentUserID(r)
	if err != nil {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	if err := s.svc.RevokeAPIToken(r.Context(), userID, r.FormValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (s *Server) setSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "potpuri_session", Value: token, Path: "/", HttpOnly: true, Secure: s.config.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: 30 * 24 * 60 * 60})
}

func (s *Server) stripeConfigured() bool {
	return s.config.StripeSecretKey != "" && s.config.StripePriceID != "" && s.config.StripeWebhookSecret != ""
}

func (s *Server) createStripeCheckoutSession(r *http.Request, userID, email string) (string, error) {
	baseURL := strings.TrimRight(s.config.PublicURL, "/")
	if baseURL == "" {
		scheme := "https"
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			scheme = "http"
		}
		baseURL = scheme + "://" + r.Host
	}
	form := url.Values{}
	form.Set("mode", "subscription")
	form.Set("line_items[0][price]", s.config.StripePriceID)
	form.Set("line_items[0][quantity]", "1")
	form.Set("success_url", baseURL+"/account?patron=success")
	form.Set("cancel_url", baseURL+"/patron")
	form.Set("client_reference_id", userID)
	form.Set("customer_email", email)
	form.Set("metadata[user_id]", userID)
	form.Set("subscription_data[metadata][user_id]", userID)

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://api.stripe.com/v1/checkout/sessions", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(s.config.StripeSecretKey, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("Stripe checkout failed: %s", strings.TrimSpace(string(body)))
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.URL == "" {
		return "", fmt.Errorf("Stripe checkout response did not include a URL")
	}
	return out.URL, nil
}

func (s *Server) stripeWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.stripeConfigured() {
		http.Error(w, "Stripe is not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := verifyStripeSignature(body, r.Header.Get("Stripe-Signature"), s.config.StripeWebhookSecret, time.Now()); err != nil {
		http.Error(w, "invalid Stripe signature", http.StatusBadRequest)
		return
	}
	var event stripeEvent
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.applyStripeEvent(r.Context(), event); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type stripeEvent struct {
	Type string `json:"type"`
	Data struct {
		Object json.RawMessage `json:"object"`
	} `json:"data"`
}

func (s *Server) applyStripeEvent(ctx context.Context, event stripeEvent) error {
	switch event.Type {
	case "checkout.session.completed":
		var session struct {
			ClientReferenceID string            `json:"client_reference_id"`
			Metadata          map[string]string `json:"metadata"`
		}
		if err := json.Unmarshal(event.Data.Object, &session); err != nil {
			return err
		}
		userID := firstNonEmpty(session.ClientReferenceID, session.Metadata["user_id"])
		if userID == "" {
			return fmt.Errorf("Stripe checkout session is missing user_id")
		}
		return s.svc.SetPatron(ctx, userID, true)
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted":
		var sub struct {
			Status   string            `json:"status"`
			Metadata map[string]string `json:"metadata"`
		}
		if err := json.Unmarshal(event.Data.Object, &sub); err != nil {
			return err
		}
		userID := sub.Metadata["user_id"]
		if userID == "" {
			return fmt.Errorf("Stripe subscription is missing user_id")
		}
		return s.svc.SetPatron(ctx, userID, sub.Status == "active" || sub.Status == "trialing")
	default:
		return nil
	}
}

func verifyStripeSignature(payload []byte, header, secret string, now time.Time) error {
	var timestamp string
	var signatures []string
	for _, part := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch key {
		case "t":
			timestamp = value
		case "v1":
			signatures = append(signatures, value)
		}
	}
	if timestamp == "" || len(signatures) == 0 {
		return fmt.Errorf("missing signature")
	}
	unixSeconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return err
	}
	signedAt := time.Unix(unixSeconds, 0)
	if now.Sub(signedAt) > 5*time.Minute || signedAt.Sub(now) > 5*time.Minute {
		return fmt.Errorf("stale signature")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	for _, sig := range signatures {
		if hmac.Equal([]byte(expected), []byte(sig)) {
			return nil
		}
	}
	return fmt.Errorf("signature mismatch")
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

func joinTags(tags []string) string {
	return strings.Join(tags, ", ")
}

func itemInputFromClipboardText(text, title, sourceURL string) usecase.CreateItemInput {
	text = strings.TrimSpace(text)
	title = strings.TrimSpace(title)
	sourceURL = strings.TrimSpace(sourceURL)
	if sourceURL == "" && isLikelyURL(text) {
		sourceURL = text
	}
	if text == "" && sourceURL == "" && title == "" {
		return usecase.CreateItemInput{}
	}
	if title == "" {
		title = defaultTitle(sourceURL, "", text)
	}
	body := text
	if sourceURL != "" && body == sourceURL {
		body = ""
	}
	return usecase.CreateItemInput{
		Type:      inferredType(sourceURL, ""),
		Title:     title,
		Body:      body,
		SourceURL: sourceURL,
		Tags:      []string{"clipboard"},
	}
}

func hasCaptureContent(input usecase.CreateItemInput) bool {
	return strings.TrimSpace(input.Title) != "" ||
		strings.TrimSpace(input.Body) != "" ||
		strings.TrimSpace(input.SourceURL) != ""
}

func itemInputFromRequest(r *http.Request) (usecase.CreateItemInput, error) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		return usecase.CreateItemInput{}, err
	}
	sourceURL := strings.TrimSpace(r.FormValue("source_url"))
	body := strings.TrimSpace(r.FormValue("body"))
	title := strings.TrimSpace(r.FormValue("title"))
	blobs, firstFilename, err := uploadedFiles(r)
	if err != nil {
		return usecase.CreateItemInput{}, err
	}
	if title == "" {
		title = defaultTitle(sourceURL, firstFilename, body)
	}
	return usecase.CreateItemInput{
		Type:      inferredType(sourceURL, firstFilename),
		Title:     title,
		Body:      body,
		SourceURL: sourceURL,
		Tags:      splitCSV(r.FormValue("tags")),
		Blobs:     blobs,
	}, nil
}

func uploadedFiles(r *http.Request) ([]usecase.BlobInput, string, error) {
	if r.MultipartForm == nil || r.MultipartForm.File == nil {
		return nil, "", nil
	}
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		files = r.MultipartForm.File["file"]
	}
	var blobs []usecase.BlobInput
	firstFilename := ""
	for _, header := range files {
		if header == nil || header.Filename == "" {
			continue
		}
		if firstFilename == "" {
			firstFilename = header.Filename
		}
		file, err := header.Open()
		if err != nil {
			return nil, "", err
		}
		const httpUploadCap = 100 * 1024 * 1024 // patron max; use-case enforces per-tier limits
		content, readErr := io.ReadAll(io.LimitReader(file, httpUploadCap+1))
		closeErr := file.Close()
		if readErr != nil {
			return nil, "", readErr
		}
		if closeErr != nil {
			return nil, "", closeErr
		}
		if len(content) > httpUploadCap {
			return nil, "", fmt.Errorf("%s exceeds the maximum upload size of 100 MB", header.Filename)
		}
		contentType := header.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		blobs = append(blobs, usecase.BlobInput{Filename: header.Filename, ContentType: contentType, Content: content})
	}
	return blobs, firstFilename, nil
}

func splitUploadedFiles(body string) (string, string) {
	const heading = "## Uploaded files\n\n"
	if strings.HasPrefix(body, heading) {
		return "", strings.TrimSpace(body)
	}
	const marker = "\n\n" + heading
	index := strings.Index(body, marker)
	if index < 0 {
		return body, ""
	}
	return strings.TrimRight(body[:index], "\n"), strings.TrimSpace(body[index:])
}

func appendUploadedFiles(body, uploads string) string {
	uploads = strings.TrimSpace(uploads)
	if uploads == "" {
		return body
	}
	body = strings.TrimRight(body, "\n")
	if body == "" {
		return uploads
	}
	return body + "\n\n" + uploads
}

func inferredType(sourceURL, firstFilename string) domain.ItemType {
	if firstFilename != "" {
		return domain.ItemTypeFile
	}
	if sourceURL != "" {
		return domain.ItemTypeURL
	}
	return domain.ItemTypeNote
}

func isLikelyURL(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func defaultTitle(sourceURL, firstFilename, body string) string {
	if sourceURL != "" {
		return sourceURL
	}
	if firstFilename != "" {
		return firstFilename
	}
	firstLine := strings.TrimSpace(strings.Split(body, "\n")[0])
	if firstLine != "" {
		if len(firstLine) > 80 {
			return firstLine[:80]
		}
		return firstLine
	}
	return "Untitled"
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

var uploadedFileBlockRE = regexp.MustCompile("(?s)### ([^\n]+)\n\nContent-Type: ([^\n]+)\nSize: [0-9]+ bytes\n\n```base64\n([A-Za-z0-9+/=\\r\\n]+)\n```")

// markdownRenderer converts note text to HTML. Raw HTML in the source is
// dropped (no WithUnsafe), and the result is still passed through bluemonday,
// so stored notes cannot inject script or javascript: URLs.
var markdownRenderer = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithRendererOptions(goldmarkhtml.WithHardWraps()),
)

var bodySanitizer = bluemonday.UGCPolicy()

func renderMarkdown(text string) string {
	var buf bytes.Buffer
	if err := markdownRenderer.Convert([]byte(text), &buf); err != nil {
		return template.HTMLEscapeString(text)
	}
	return bodySanitizer.Sanitize(buf.String())
}

func renderBody(body string) template.HTML {
	var out strings.Builder
	last := 0
	for _, match := range uploadedFileBlockRE.FindAllStringSubmatchIndex(body, -1) {
		out.WriteString(renderMarkdown(body[last:match[0]]))
		filename := body[match[2]:match[3]]
		contentType := body[match[4]:match[5]]
		rawBase64 := body[match[6]:match[7]]
		if dataURL, ok := imageDataURL(contentType, rawBase64); ok {
			out.WriteString(`<figure class="uploaded-image-frame"><img class="uploaded-image" src="`)
			out.WriteString(template.HTMLEscapeString(dataURL))
			out.WriteString(`" alt="`)
			out.WriteString(template.HTMLEscapeString(filename))
			out.WriteString(`"><figcaption>`)
			out.WriteString(template.HTMLEscapeString(filename))
			out.WriteString(`</figcaption></figure>`)
		} else {
			out.WriteString(template.HTMLEscapeString(body[match[0]:match[1]]))
		}
		last = match[1]
	}
	out.WriteString(renderMarkdown(body[last:]))
	return template.HTML(out.String())
}

var snippetWhitespaceRE = regexp.MustCompile(`\s+`)

// snippet renders a short, single-line plain-text teaser for the collapsed
// entry list: editable text only (uploaded-file blocks stripped), Markdown
// punctuation flattened, collapsed whitespace, truncated to ~160 chars.
func snippet(body string) string {
	text, _ := splitUploadedFiles(body)
	text = snippetWhitespaceRE.ReplaceAllString(text, " ")
	text = strings.TrimSpace(strings.Trim(text, "#>*`-_ "))
	const limit = 160
	if len(text) > limit {
		text = strings.TrimSpace(text[:limit]) + "…"
	}
	return text
}

func fmtDate(t time.Time) string {
	return t.Format("Jan 2, 2006")
}

func imageDataURL(contentType, rawBase64 string) (string, bool) {
	contentType = strings.TrimSpace(strings.ToLower(contentType))
	switch contentType {
	case "image/png", "image/jpeg", "image/gif", "image/webp":
	default:
		return "", false
	}
	encoded := strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t', ' ':
			return -1
		default:
			return r
		}
	}, rawBase64)
	if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
		return "", false
	}
	return "data:" + contentType + ";base64," + encoded, true
}

func isImageBlob(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "image/")
}

func blobURL(blobID string) string {
	return "/items/blob?id=" + template.URLQueryEscaper(blobID)
}

func blobDownloadURL(blobID string) string {
	return "/items/blob?id=" + template.URLQueryEscaper(blobID) + "&download=1"
}

func manifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json")
	_, _ = w.Write([]byte(`{"name":"Potpuri","short_name":"Potpuri","start_url":"/","display":"standalone","background_color":"#ffffff","theme_color":"#111111","icons":[{"src":"/static/rose.svg","sizes":"any","type":"image/svg+xml","purpose":"any maskable"}],"share_target":{"action":"/share","method":"GET","params":{"title":"title","text":"text","url":"url"}}}`))
}

func serviceWorker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript")
	_, _ = w.Write([]byte(`self.addEventListener("install",event=>self.skipWaiting());self.addEventListener("fetch",()=>{});`))
}

func roseLogo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	_, _ = w.Write(roseSVG)
}
