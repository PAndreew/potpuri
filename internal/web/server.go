package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"

	"potpuri/internal/domain"
	"potpuri/internal/usecase"
)

type Server struct {
	svc *usecase.Service
	tpl *template.Template
}

func NewServer(svc *usecase.Service) *Server {
	return &Server{svc: svc, tpl: template.Must(template.New("index").Parse(indexHTML))}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.home)
	mux.HandleFunc("/register", s.register)
	mux.HandleFunc("/login", s.login)
	mux.HandleFunc("/logout", s.logout)
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/items", s.createItemHTML)
	mux.HandleFunc("/api/items", s.itemsAPI)
	mux.HandleFunc("/api/clipboard", s.clipboardAPI)
	mux.HandleFunc("/manifest.webmanifest", manifest)
	mux.HandleFunc("/sw.js", serviceWorker)
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
	_ = s.tpl.Execute(w, map[string]any{"UserID": userID, "Items": items, "Query": r.URL.Query().Get("q")})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
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
		http.Redirect(w, r, "/", http.StatusSeeOther)
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
	var input struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	item, err := s.svc.CreateItem(r.Context(), usecase.CreateItemInput{UserID: userID, Type: domain.ItemTypeNote, Title: "Clipboard", Body: input.Text, Tags: []string{"clipboard"}})
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

func inferredType(sourceURL, firstFilename string) domain.ItemType {
	if firstFilename != "" {
		return domain.ItemTypeFile
	}
	if sourceURL != "" {
		return domain.ItemTypeURL
	}
	return domain.ItemTypeNote
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

func manifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json")
	_, _ = w.Write([]byte(`{"name":"Potpuri","short_name":"Potpuri","start_url":"/","display":"standalone","background_color":"#ffffff","theme_color":"#111111","icons":[]}`))
}

func serviceWorker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript")
	_, _ = w.Write([]byte(`self.addEventListener("install",event=>self.skipWaiting());self.addEventListener("fetch",()=>{});`))
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="manifest" href="/manifest.webmanifest">
  <title>Potpuri</title>
  <style>
    body{font-family:system-ui,sans-serif;max-width:760px;margin:32px auto;padding:0 16px;line-height:1.45}
    input,textarea,button{font:inherit;width:100%;box-sizing:border-box;margin:4px 0 12px;padding:8px}
    button{width:auto}
    header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
    header h1{font-size:1.5rem;margin:0}
    header form{margin:0}
    .search{display:flex;gap:8px;align-items:start}
    .search input{flex:1}
    .field{margin-bottom:12px}
    label{display:block;font-size:.9rem;color:#333}
    article{border-top:1px solid #ddd;padding:16px 0}
    small{color:#555}
    pre{white-space:pre-wrap}
  </style>
</head>
<body>
  {{if .UserID}}
    <header>
      <h1>Potpuri</h1>
      <form method="post" action="/logout"><button>Log out</button></form>
    </header>
    <form class="search" method="get" action="/">
      <input name="q" value="{{.Query}}" placeholder="Search">
      <button>Search</button>
    </form>
    <form method="post" action="/items" enctype="multipart/form-data">
      <input name="title" placeholder="Title">
      <div class="field">
        <label for="source_url">URL</label>
        <input id="source_url" name="source_url" placeholder="https://example.com">
      </div>
      <div class="field">
        <label for="body">MD note</label>
        <textarea id="body" name="body" rows="8" placeholder="Markdown note"></textarea>
      </div>
      <div class="field">
        <label for="files">File upload</label>
        <input id="files" name="files" type="file" multiple>
      </div>
      <input name="tags" placeholder="tags, comma separated">
      <button>Add</button>
      <button type="button" onclick="addClipboard()">Add clipboard</button>
    </form>
    {{range .Items}}
      <article>
        <h2>{{.Title}}</h2>
        <small>{{.Type}} · {{.CreatedAt}} · {{range .Tags}}#{{.}} {{end}}</small>
        {{if .SourceURL}}<p><a href="{{.SourceURL}}">{{.SourceURL}}</a></p>{{end}}
        <pre>{{.Body}}</pre>
      </article>
    {{else}}
      <p>No entries yet.</p>
    {{end}}
    <script>
      navigator.serviceWorker && navigator.serviceWorker.register('/sw.js');
      async function addClipboard(){
        const text = await navigator.clipboard.readText();
        await fetch('/api/clipboard',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({text})});
        location.reload();
      }
    </script>
  {{else}}
    <h2>Register</h2>
    <form method="post" action="/register">
      <input name="email" type="email" placeholder="Email">
      <input name="password" type="password" placeholder="Password">
      <button>Register</button>
    </form>
    <h2>Log in</h2>
    <form method="post" action="/login">
      <input name="email" type="email" placeholder="Email">
      <input name="password" type="password" placeholder="Password">
      <button>Log in</button>
    </form>
  {{end}}
</body>
</html>`
