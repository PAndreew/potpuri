package web

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/microcosm-cc/bluemonday"
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
	"renderBody":  renderBody,
	"isImageBlob": isImageBlob,
	"blobURL":     blobURL,
	"joinTags":    joinTags,
	"snippet":     snippet,
	"fmtDate":     fmtDate,
}

type Server struct {
	svc         *usecase.Service
	index       *template.Template
	loginTpl    *template.Template
	registerTpl *template.Template
	addTpl      *template.Template
	editTpl     *template.Template
	tokensTpl   *template.Template
	config      Config
}

type Config struct {
	AllowRegistration bool
	SecureCookies     bool
}

func NewServer(svc *usecase.Service) *Server {
	return NewServerWithConfig(svc, Config{AllowRegistration: true})
}

func NewServerWithConfig(svc *usecase.Service, config Config) *Server {
	return &Server{
		svc:         svc,
		index:       parsePage("index.html"),
		loginTpl:    parsePage("login.html"),
		registerTpl: parsePage("register.html"),
		addTpl:      parsePage("add.html"),
		editTpl:     parsePage("edit.html"),
		tokensTpl:   parsePage("tokens.html"),
		config:      config,
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
	mux.HandleFunc("/share", s.shareHTML)
	mux.HandleFunc("/tokens", s.tokensHTML)
	mux.HandleFunc("/tokens/revoke", s.revokeTokenHTML)
	mux.HandleFunc("/items", s.createItemHTML)
	mux.HandleFunc("/items/edit", s.editItemHTML)
	mux.HandleFunc("/items/delete", s.deleteItemHTML)
	mux.HandleFunc("/items/blob", s.blobHTML)
	mux.HandleFunc("/api/items", corsAPI(s.itemsAPI))
	mux.HandleFunc("/api/clipboard", corsAPI(s.clipboardAPI))
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
	token, err := s.svc.Login(r.Context(), user.Email, r.FormValue("password"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	s.setSession(w, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		_ = s.loginTpl.Execute(w, map[string]any{"AllowRegistration": s.config.AllowRegistration})
		return
	}
	token, err := s.svc.Login(r.Context(), r.FormValue("email"), r.FormValue("password"))
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.setSession(w, token)
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
		content, readErr := io.ReadAll(io.LimitReader(file, 32<<20+1))
		closeErr := file.Close()
		if readErr != nil {
			return nil, "", readErr
		}
		if closeErr != nil {
			return nil, "", closeErr
		}
		if len(content) > 32<<20 {
			return nil, "", fmt.Errorf("%s is larger than 32MB", header.Filename)
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
