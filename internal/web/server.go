package web

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"regexp"
	"strings"

	"potpuri/internal/domain"
	"potpuri/internal/usecase"
)

//go:embed static/rose.svg
var roseSVG []byte

type Server struct {
	svc         *usecase.Service
	index       *template.Template
	loginTpl    *template.Template
	registerTpl *template.Template
	addTpl      *template.Template
	editTpl     *template.Template
}

func NewServer(svc *usecase.Service) *Server {
	return &Server{
		svc:         svc,
		index:       template.Must(template.New("index").Funcs(template.FuncMap{"renderBody": renderBody}).Parse(indexHTML)),
		loginTpl:    template.Must(template.New("login").Parse(loginHTML)),
		registerTpl: template.Must(template.New("register").Parse(registerHTML)),
		addTpl:      template.Must(template.New("add").Parse(addHTML)),
		editTpl:     template.Must(template.New("edit").Funcs(template.FuncMap{"joinTags": joinTags}).Parse(editHTML)),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.home)
	mux.HandleFunc("/add", s.add)
	mux.HandleFunc("/register", s.register)
	mux.HandleFunc("/login", s.login)
	mux.HandleFunc("/logout", s.logout)
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/items", s.createItemHTML)
	mux.HandleFunc("/items/edit", s.editItemHTML)
	mux.HandleFunc("/items/delete", s.deleteItemHTML)
	mux.HandleFunc("/api/items", s.itemsAPI)
	mux.HandleFunc("/api/clipboard", s.clipboardAPI)
	mux.HandleFunc("/manifest.webmanifest", manifest)
	mux.HandleFunc("/sw.js", serviceWorker)
	mux.HandleFunc("/static/rose.svg", roseLogo)
	return mux
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
	setSession(w, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		_ = s.loginTpl.Execute(w, nil)
		return
	}
	token, err := s.svc.Login(r.Context(), r.FormValue("email"), r.FormValue("password"))
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	setSession(w, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "potpuri_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
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
	cookie, err := r.Cookie("potpuri_session")
	if err != nil {
		return "", err
	}
	return s.svc.UserIDForSession(r.Context(), cookie.Value)
}

func setSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "potpuri_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 30 * 24 * 60 * 60})
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
	filesBody, firstFilename, err := uploadedFilesBody(r)
	if err != nil {
		return usecase.CreateItemInput{}, err
	}
	if filesBody != "" {
		if body != "" {
			body += "\n\n"
		}
		body += filesBody
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
	}, nil
}

func uploadedFilesBody(r *http.Request) (string, string, error) {
	if r.MultipartForm == nil || r.MultipartForm.File == nil {
		return "", "", nil
	}
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		files = r.MultipartForm.File["file"]
	}
	var out strings.Builder
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
			return "", "", err
		}
		content, readErr := io.ReadAll(io.LimitReader(file, 32<<20+1))
		closeErr := file.Close()
		if readErr != nil {
			return "", "", readErr
		}
		if closeErr != nil {
			return "", "", closeErr
		}
		if len(content) > 32<<20 {
			return "", "", fmt.Errorf("%s is larger than 32MB", header.Filename)
		}
		if out.Len() == 0 {
			out.WriteString("## Uploaded files\n\n")
		}
		contentType := header.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		out.WriteString(fmt.Sprintf("### %s\n\nContent-Type: %s\nSize: %d bytes\n\n```base64\n%s\n```\n\n",
			header.Filename,
			contentType,
			len(content),
			base64.StdEncoding.EncodeToString(content),
		))
	}
	return strings.TrimSpace(out.String()), firstFilename, nil
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

func renderBody(body string) template.HTML {
	var out strings.Builder
	last := 0
	for _, match := range uploadedFileBlockRE.FindAllStringSubmatchIndex(body, -1) {
		out.WriteString(template.HTMLEscapeString(body[last:match[0]]))
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
	out.WriteString(template.HTMLEscapeString(body[last:]))
	return template.HTML(out.String())
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

func manifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json")
	_, _ = w.Write([]byte(`{"name":"Potpuri","short_name":"Potpuri","start_url":"/","display":"standalone","background_color":"#ffffff","theme_color":"#111111","icons":[{"src":"/static/rose.svg","sizes":"any","type":"image/svg+xml","purpose":"any maskable"}]}`))
}

func serviceWorker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript")
	_, _ = w.Write([]byte(`self.addEventListener("install",event=>self.skipWaiting());self.addEventListener("fetch",()=>{});`))
}

func roseLogo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	_, _ = w.Write(roseSVG)
}

const baseCSS = `
    body{font-family:system-ui,sans-serif;max-width:760px;margin:32px auto;padding:0 16px;line-height:1.45}
    body{overflow-wrap:anywhere}
    input,textarea,button,.button{font:inherit;width:100%;box-sizing:border-box;margin:4px 0 12px;padding:8px}
    button,.button{width:auto;border:1px solid #111;border-radius:999px;background:#111;color:#fff;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;line-height:1.2}
    .button.ghost,button.ghost{background:transparent;color:#111;border-color:#bbb}
    .actions{display:flex;gap:8px;align-items:center;margin-top:8px}
    .actions form{margin:0}
    a{color:#0645ad}
    header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
    header h1{font-size:1.5rem;margin:0}
    .brand{display:flex;align-items:center;gap:8px;color:inherit;text-decoration:none}
    .brand img{width:28px;height:28px}
    .signed-out{min-height:calc(100vh - 64px);display:flex;align-items:center;justify-content:center;text-align:center}
    .intro{max-width:480px;margin:0 auto}
    .intro img{width:84px;height:84px;margin-bottom:16px}
    .intro h1{font-size:2rem;margin:0 0 12px}
    .intro p{margin:0 0 24px;color:#333}
    .intro .button{min-width:112px}
    .auth-page{min-height:calc(100vh - 64px);display:flex;align-items:center;justify-content:center}
    .auth-form{width:100%;max-width:360px}
    .auth-logo{display:block;width:64px;height:64px;margin:0 auto 16px}
    .auth-form h1{text-align:center;font-size:2rem;margin:0 0 20px}
    .auth-actions{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;margin-top:4px}
    .auth-actions button{margin:0;padding:8px 16px;min-width:112px}
    .signup-link{color:#0645ad;display:inline-flex;padding:8px 16px}
    header form{margin:0}
    .top-link{display:block;margin:0 0 12px}
    .search{display:flex;gap:8px;align-items:start}
    .search input{flex:1}
    .field{margin-bottom:12px}
    label{display:block;font-size:.9rem;color:#333}
    article{border-top:1px solid #ddd;padding:16px 0}
    article h2{margin-bottom:4px}
    small{color:#555}
    pre,.item-body{white-space:pre-wrap;overflow-wrap:anywhere}
    .uploaded-image-frame{margin:12px 0}
    .uploaded-image{display:block;max-width:100%;height:auto;border-radius:12px}
    .uploaded-image-frame figcaption{font-size:.85rem;color:#555;margin-top:6px}
`

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="manifest" href="/manifest.webmanifest">
  <link rel="icon" href="/static/rose.svg" type="image/svg+xml">
  <title>Potpuri</title>
  <style>
` + baseCSS + `
  </style>
</head>
<body>
  {{if .UserID}}
    <header>
      <div class="brand"><img src="/static/rose.svg" alt=""><h1>Potpuri</h1></div>
      <form method="post" action="/logout"><button class="ghost">Log out</button></form>
    </header>
    <a class="top-link" href="/add">Add to Potpuri</a>
    <form class="search" method="get" action="/">
      <input name="q" value="{{.Query}}" placeholder="Search">
      <button>Search</button>
    </form>
    {{range .Items}}
      <article>
        <h2>{{.Title}}</h2>
        <small>{{.Type}} · {{.CreatedAt}} · {{range .Tags}}#{{.}} {{end}}</small>
        {{if .SourceURL}}<p><a href="{{.SourceURL}}">{{.SourceURL}}</a></p>{{end}}
        <div class="item-body">{{renderBody .Body}}</div>
        <div class="actions">
          <a class="button" href="/items/edit?id={{.ID}}">Edit</a>
          <form method="post" action="/items/delete">
          <input type="hidden" name="id" value="{{.ID}}">
            <button>Delete</button>
          </form>
        </div>
      </article>
    {{else}}
      <p>No entries yet.</p>
    {{end}}
    <script>
      navigator.serviceWorker && navigator.serviceWorker.register('/sw.js');
    </script>
  {{else}}
    <main class="signed-out">
      <div class="intro">
        <img src="/static/rose.svg" alt="">
        <h1>Potpuri</h1>
        <p>Potpuri is a minimalistic digital treasue trove. You can save links, files, photos, and markdown notes for later. No tracking, no LLM bullshit.</p>
        <a class="button" href="/login">Sign in</a>
      </div>
    </main>
  {{end}}
</body>
</html>`

const loginHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="manifest" href="/manifest.webmanifest">
  <link rel="icon" href="/static/rose.svg" type="image/svg+xml">
  <title>Sign in - Potpuri</title>
  <style>
` + baseCSS + `
  </style>
</head>
<body>
  <main class="auth-page">
    <form class="auth-form" method="post" action="/login">
      <img class="auth-logo" src="/static/rose.svg" alt="">
      <h1>Sign in</h1>
      <input name="email" type="email" placeholder="Email">
      <input name="password" type="password" placeholder="Password">
      <div class="auth-actions">
        <button>Sign in</button>
        <a class="signup-link" href="/register">Sign up</a>
      </div>
    </form>
  </main>
</body>
</html>`

const registerHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="manifest" href="/manifest.webmanifest">
  <link rel="icon" href="/static/rose.svg" type="image/svg+xml">
  <title>Sign up - Potpuri</title>
  <style>
` + baseCSS + `
  </style>
</head>
<body>
  <main class="auth-page">
    <form class="auth-form" method="post" action="/register">
      <img class="auth-logo" src="/static/rose.svg" alt="">
      <h1>Sign up</h1>
      <input name="email" type="email" placeholder="Email">
      <input name="password" type="password" placeholder="Password">
      <div class="auth-actions">
        <button>Sign up</button>
      </div>
    </form>
  </main>
</body>
</html>`

const addHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="manifest" href="/manifest.webmanifest">
  <link rel="icon" href="/static/rose.svg" type="image/svg+xml">
  <title>Add to Potpuri</title>
  <style>
` + baseCSS + `
  </style>
</head>
<body>
  <header>
    <div class="brand"><img src="/static/rose.svg" alt=""><h1>Potpuri</h1></div>
    <form method="post" action="/logout"><button class="ghost">Log out</button></form>
  </header>
  <a class="top-link" href="/">Back to items</a>
  <form method="post" action="/items" enctype="multipart/form-data">
    <input name="title" placeholder="Title">
    <textarea id="body" name="body" rows="10" placeholder="Paste or write anything"></textarea>
    <input id="files" name="files" type="file" multiple>
    <input name="source_url" placeholder="Optional source URL">
    <input name="tags" placeholder="tags, comma separated">
    <button class="add-button">Add</button>
  </form>
  <script>
    navigator.serviceWorker && navigator.serviceWorker.register('/sw.js');
  </script>
</body>
</html>`

const editHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="manifest" href="/manifest.webmanifest">
  <link rel="icon" href="/static/rose.svg" type="image/svg+xml">
  <title>Edit {{.Item.Title}} - Potpuri</title>
  <style>
` + baseCSS + `
  </style>
</head>
<body>
  <header>
    <div class="brand"><img src="/static/rose.svg" alt=""><h1>Potpuri</h1></div>
    <form method="post" action="/logout"><button class="ghost">Log out</button></form>
  </header>
  <a class="top-link" href="/">Back to items</a>
  <form method="post" action="/items/edit" enctype="multipart/form-data">
    <input type="hidden" name="id" value="{{.Item.ID}}">
    <input name="title" placeholder="Title" value="{{.Item.Title}}">
    <textarea id="body" name="body" rows="10" placeholder="Paste or write anything">{{.EditableBody}}</textarea>
    <input id="files" name="files" type="file" multiple>
    <input name="source_url" placeholder="Optional source URL" value="{{.Item.SourceURL}}">
    <input name="tags" placeholder="tags, comma separated" value="{{joinTags .Item.Tags}}">
    <button>Save changes</button>
  </form>
  <script>
    navigator.serviceWorker && navigator.serviceWorker.register('/sw.js');
  </script>
</body>
</html>`
