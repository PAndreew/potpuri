package web

import (
	_ "embed"
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

//go:embed static/rose.svg
var roseSVG []byte

type Server struct {
	svc    *usecase.Service
	index  *template.Template
	addTpl *template.Template
}

func NewServer(svc *usecase.Service) *Server {
	return &Server{
		svc:    svc,
		index:  template.Must(template.New("index").Parse(indexHTML)),
		addTpl: template.Must(template.New("add").Parse(addHTML)),
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
    input,textarea,button{font:inherit;width:100%;box-sizing:border-box;margin:4px 0 12px;padding:8px}
    button{width:auto}
    a{color:#0645ad}
    header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
    header h1{font-size:1.5rem;margin:0}
    .brand{display:flex;align-items:center;gap:8px}
    .brand img{width:28px;height:28px}
    header form{margin:0}
    .top-link{display:block;margin:0 0 12px}
    .search{display:flex;gap:8px;align-items:start}
    .search input{flex:1}
    .field{margin-bottom:12px}
    label{display:block;font-size:.9rem;color:#333}
    article{border-top:1px solid #ddd;padding:16px 0}
    article h2{margin-bottom:4px}
    article form{margin-top:8px}
    small{color:#555}
    pre{white-space:pre-wrap}
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
      <form method="post" action="/logout"><button>Log out</button></form>
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
        <pre>{{.Body}}</pre>
        <form method="post" action="/items/delete">
          <input type="hidden" name="id" value="{{.ID}}">
          <button>Delete</button>
        </form>
      </article>
    {{else}}
      <p>No entries yet.</p>
    {{end}}
    <script>
      navigator.serviceWorker && navigator.serviceWorker.register('/sw.js');
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
    <form method="post" action="/logout"><button>Log out</button></form>
  </header>
  <a class="top-link" href="/">Back to items</a>
  <form method="post" action="/items" enctype="multipart/form-data">
    <input name="title" placeholder="Title">
    <textarea id="body" name="body" rows="10" placeholder="Paste or write anything"></textarea>
    <input id="files" name="files" type="file" multiple>
    <input name="source_url" placeholder="Optional source URL">
    <input name="tags" placeholder="tags, comma separated">
    <button>Add</button>
    <button id="clipboard-button" type="button" onclick="addClipboard()">Add clipboard</button>
    <p id="clipboard-status" role="status"></p>
  </form>
  <script>
    navigator.serviceWorker && navigator.serviceWorker.register('/sw.js');
    async function addClipboard(){
      const button = document.getElementById("clipboard-button");
      const status = document.getElementById("clipboard-status");
      const body = document.getElementById("body");
      const files = document.getElementById("files");
      const form = new FormData();
      let text = "";
      button.disabled = true;
      status.textContent = "Reading clipboard...";
      const timeout = (ms) => new Promise((_, reject) => setTimeout(() => reject(new Error("Clipboard read timed out")), ms));
      const withTimeout = (promise) => Promise.race([promise, timeout(2500)]);
      if (navigator.clipboard && navigator.clipboard.readText) {
        try {
          text = await withTimeout(navigator.clipboard.readText());
        } catch (err) {
          status.textContent = "Clipboard text was not available. Trying files...";
        }
      }
      if (navigator.clipboard && navigator.clipboard.read) {
        try {
          const items = await withTimeout(navigator.clipboard.read());
          for (const item of items) {
            for (const type of item.types) {
              const blob = await withTimeout(item.getType(type));
              if (type.startsWith("text/")) {
                text += await withTimeout(blob.text());
              } else {
                const ext = type.includes("/") ? type.split("/")[1].replace(/[^a-z0-9.+-]/gi, "") : "bin";
                form.append("files", new File([blob], "clipboard." + ext, {type}));
              }
            }
          }
        } catch (err) {
          status.textContent = "Clipboard file access was not available.";
        }
      }
      if (!text && body.value.trim()) {
        text = body.value;
      }
      for (const file of files.files) {
        form.append("files", file);
      }
      if (!text && !form.has("files")) {
        status.textContent = "Nothing to add. Paste text here or choose a file, then try again.";
        button.disabled = false;
        return;
      }
      form.append("body", text);
      status.textContent = "Adding...";
      const response = await fetch("/api/clipboard", {method:"POST", body:form});
      if (!response.ok) {
        status.textContent = (await response.text()).trim() || "Could not add clipboard.";
        button.disabled = false;
        return;
      }
      location.href = "/";
    }
  </script>
</body>
</html>`
