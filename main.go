package main // ausführbares Programm

import ( // Standard- und Fremdpakete
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"     // leichtgewichtiger HTTP-Router
	"github.com/golang-jwt/jwt/v5" // JWT-Erzeugung/Verifikation
)

// UploadSession beschreibt eine laufende Upload-Transaktion (resumable).
type UploadSession struct {
	ID        string    // eindeutige Session-ID
	PathRel   string    // Zielpfad relativ zum DATA_DIR
	TempPath  string    // temporäre Datei für Chunks
	Size      int64     // erwartete Gesamtgröße der Zieldatei
	SHA256    string    // optionaler erwarteter SHA256-Hash (hex)
	Offset    int64     // aktuell geschriebener Offset (Next-Byte)
	CreatedAt time.Time // erstellt am
	UpdatedAt time.Time // zuletzt aktualisiert
}

// Server hält globale Server-Settings/Zustand.
type Server struct {
	dataDir    string                    // Wurzel für endgültige Dateien
	uploadsDir string                    // Wurzel für temporäre Uploads
	jwtSecret  []byte                    // HMAC-Secret für JWT
	pats       map[string]struct{}       // erlaubte PATs (Personal Access Tokens)
	sessions   map[string]*UploadSession // aktive Upload-Sessions
	mu         sync.RWMutex              // Schutz für sessions
}

// envOr liest eine Umgebungsvariable oder liefert einen Default.
func envOr(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}

// NewServer initialisiert Verzeichnisse, lädt Env-Config und erzeugt den Server.
func NewServer() *Server {
	dataDir := envOr("DATA_DIR", "/srv/autosync/data")
	uploadsDir := envOr("UPLOADS_DIR", "/srv/autosync/uploads")
	_ = os.MkdirAll(dataDir, 0755)
	_ = os.MkdirAll(uploadsDir, 0755)

	jwtSecret := []byte(envOr("JWT_SECRET", "change-me-please"))

	// PATs aus Env: PAT_TOKENS="t1,t2,..." + optional FIXED_PAT="Drive-Sync"
	pats := map[string]struct{}{}
	patCSV := envOr("PAT_TOKENS", "")
	for _, t := range strings.Split(patCSV, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			pats[t] = struct{}{}
		}
	}
	if fixed := strings.TrimSpace(envOr("FIXED_PAT", "")); fixed != "" {
		pats[fixed] = struct{}{}
	}

	return &Server{
		dataDir:    dataDir,
		uploadsDir: uploadsDir,
		jwtSecret:  jwtSecret,
		pats:       pats,
		sessions:   map[string]*UploadSession{},
	}
}

// issueJWT erstellt ein signiertes JWT mit Subject + Ablaufdauer.
func (s *Server) issueJWT(subject string, dur time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"sub": subject,
		"exp": time.Now().Add(dur).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// parseBearer zieht ein "Bearer <token>" aus dem Authorization-Header.
func parseBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// authMiddleware schützt alle Routen außer den explizit öffentlichen.
// Auth ist möglich via:
// 1) Header X-PAT: <token>
// 2) Header Authorization: PAT <token>
// 3) Header Authorization: Bearer <jwt>
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	public := map[string]bool{
		"/v1/health":     true, // öffentlich
		"/v1/auth/login": true, // JWT aus PAT beziehen (optional)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// öffentliche Endpunkte durchlassen
		if public[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// 1) X-PAT prüfen
		if xpat := r.Header.Get("X-PAT"); xpat != "" {
			if _, ok := s.pats[xpat]; ok {
				next.ServeHTTP(w, r)
				return
			}
		}

		// 2) Authorization: PAT <token>
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "PAT ") {
			t := strings.TrimPrefix(auth, "PAT ")
			if _, ok := s.pats[t]; ok {
				next.ServeHTTP(w, r)
				return
			}
		}

		// 3) Optional: Bearer-JWT zulassen
		if tok := parseBearer(r); tok != "" {
			parsed, err := jwt.Parse(tok, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, errors.New("bad signing method")
				}
				return s.jwtSecret, nil
			})
			if err == nil && parsed.Valid {
				next.ServeHTTP(w, r)
				return
			}
		}

		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// writeJSON schreibt JSON-Antwort mit Statuscode.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// health: einfacher Liveness-Check.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// login: tauscht ein gültiges PAT gegen ein JWT (7 Tage gültig).
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PAT string `json:"pat"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PAT == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, ok := s.pats[in.PAT]; !ok {
		http.Error(w, "invalid pat", http.StatusUnauthorized)
		return
	}
	tok, _ := s.issueJWT("pat:"+in.PAT, 7*24*time.Hour)
	writeJSON(w, 200, map[string]string{"token": tok})
}

// randID erzeugt eine hex-kodierte Zufalls-ID von n Bytes.
func randID(n int) string { b := make([]byte, n); _, _ = rand.Read(b); return hex.EncodeToString(b) }

// safeJoin verhindert Path-Traversal und hält Pfade unterhalb der Basis.
func (s *Server) safeJoin(rel string, base string) (string, error) {
	rel = filepath.Clean(rel)
	abs := filepath.Join(base, rel)
	relBack, err := filepath.Rel(base, abs)
	if err != nil || strings.HasPrefix(relBack, "..") {
		return "", errors.New("path escapes base")
	}
	return abs, nil
}

// postUploads: Startet eine neue Upload-Session.
// Erwartet JSON mit: path, size, sha256 (optional), overwrite.
func (s *Server) postUploads(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Path      string `json:"path"`
		Size      int64  `json:"size"`
		SHA256    string `json:"sha256"`
		Overwrite bool   `json:"overwrite"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Path == "" || in.Size < 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	final, err := s.safeJoin(in.Path, s.dataDir)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	// Kollision verhindern, falls Overwrite=false
	if !in.Overwrite {
		if _, err := os.Stat(final); err == nil {
			http.Error(w, "exists", http.StatusConflict)
			return
		}
	}
	// temporäre Datei anlegen
	id := randID(12)
	tmp := filepath.Join(s.uploadsDir, id+".part")
	f, err := os.Create(tmp)
	if err != nil {
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	_ = f.Close()

	// Session registrieren
	ses := &UploadSession{
		ID:        id,
		PathRel:   in.Path,
		TempPath:  tmp,
		Size:      in.Size,
		SHA256:    strings.ToLower(in.SHA256),
		Offset:    0,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	s.mu.Lock()
	s.sessions[id] = ses
	s.mu.Unlock()

	w.Header().Set("Location", "/v1/uploads/"+id)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "path": ses.PathRel, "size": ses.Size, "offset": ses.Offset,
	})
}

// parseContentRange liest "bytes start-end/total".
func parseContentRange(v string) (start, end, total int64, err error) {
	if !strings.HasPrefix(v, "bytes ") {
		return 0, 0, 0, errors.New("bad unit")
	}
	v = strings.TrimPrefix(v, "bytes ")
	parts := strings.Split(v, "/")
	if len(parts) != 2 {
		return 0, 0, 0, errors.New("bad slash")
	}
	rangePart := parts[0]
	total, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return
	}
	se := strings.Split(rangePart, "-")
	if len(se) != 2 {
		return 0, 0, 0, errors.New("bad dash")
	}
	start, err = strconv.ParseInt(se[0], 10, 64)
	if err != nil {
		return
	}
	end, err = strconv.ParseInt(se[1], 10, 64)
	if err != nil {
		return
	}
	return
}

// headUpload: Gibt aktuellen Offset/Length der Session zurück (Resuming).
func (s *Server) headUpload(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s.mu.RLock()
	ses, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Upload-Offset", fmt.Sprintf("%d", ses.Offset))
	w.Header().Set("Upload-Length", fmt.Sprintf("%d", ses.Size))
	w.WriteHeader(http.StatusNoContent)
}

// patchUpload: Schreibt einen Chunk an die korrekte Position (per Content-Range).
func (s *Server) patchUpload(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s.mu.RLock()
	ses, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	cr := r.Header.Get("Content-Range")
	start, end, total, err := parseContentRange(cr)
	if err != nil || total != ses.Size || start != ses.Offset || end < start {
		http.Error(w, "range mismatch", http.StatusConflict)
		return
	}

	chunkLen := end - start + 1
	// Content-Length (falls gesetzt) muss zur Range passen
	if r.ContentLength > 0 && r.ContentLength != chunkLen {
		http.Error(w, "length mismatch", http.StatusBadRequest)
		return
	}

	// an Position seeken und genau chunkLen Bytes schreiben
	f, err := os.OpenFile(ses.TempPath, os.O_RDWR, 0644)
	if err != nil {
		http.Error(w, "open temp failed", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	if _, err := f.Seek(start, 0); err != nil {
		http.Error(w, "seek failed", http.StatusInternalServerError)
		return
	}
	written, err := io.CopyN(f, r.Body, chunkLen)
	if err != nil || written != chunkLen {
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}

	// Offset fortschreiben
	s.mu.Lock()
	ses.Offset = end + 1
	ses.UpdatedAt = time.Now()
	s.mu.Unlock()
	w.Header().Set("Upload-Offset", fmt.Sprintf("%d", ses.Offset))
	w.WriteHeader(http.StatusNoContent)
}

// fileSHA256 berechnet SHA256 einer Datei und liefert (hex, bytes, err).
func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// commitUpload: Prüft Vollständigkeit & Hash, verschiebt Temp-Datei ins Ziel.
func (s *Server) commitUpload(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s.mu.RLock()
	ses, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Größe prüfen
	st, err := os.Stat(ses.TempPath)
	if err != nil || st.Size() != ses.Size {
		http.Error(w, "incomplete", http.StatusConflict)
		return
	}

	// Hash berechnen und gegen erwarteten SHA256 prüfen (Header X-Content-SHA256 hat Vorrang)
	hash, _, err := fileSHA256(ses.TempPath)
	if err != nil {
		http.Error(w, "hash failed", http.StatusInternalServerError)
		return
	}
	want := strings.ToLower(r.Header.Get("X-Content-SHA256"))
	if want == "" {
		want = ses.SHA256
	}
	if want != "" && want != hash {
		http.Error(w, "hash mismatch", http.StatusPreconditionFailed)
		return
	}

	// finalen Pfad sichern/anlegen und verschieben
	final, err := s.safeJoin(ses.PathRel, s.dataDir)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(filepath.Dir(final), 0755); err != nil {
		http.Error(w, "mkdir failed", http.StatusInternalServerError)
		return
	}
	if err := os.Rename(ses.TempPath, final); err != nil {
		http.Error(w, "move failed", http.StatusInternalServerError)
		return
	}

	// ETag zurückgeben (sha256:<hex>)
	etag := "sha256:" + hash
	w.Header().Set("ETag", etag)
	writeJSON(w, http.StatusCreated, map[string]any{"path": ses.PathRel, "etag": etag})

	// Session aufräumen
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// deleteUpload: Bricht eine Session ab und löscht die Temp-Datei (falls vorhanden).
func (s *Server) deleteUpload(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s.mu.Lock()
	if ses, ok := s.sessions[id]; ok {
		_ = os.Remove(ses.TempPath)
		delete(s.sessions, id)
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// listFiles: Listet Einträge in einem Verzeichnis unterhalb DATA_DIR.
// Optional: ?with_etag=true berechnet sha256 für Dateien (teuer!).
func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rel := q.Get("path")
	withEtag := q.Get("with_etag") == "true"

	abs, err := s.safeJoin(rel, s.dataDir)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	ents, err := os.ReadDir(abs)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	type entry struct {
		Name  string  `json:"name"`
		Path  string  `json:"path"`
		Size  int64   `json:"size"`
		Mtime string  `json:"mtime"`
		IsDir bool    `json:"is_dir"`
		Etag  *string `json:"etag"`
	}

	out := []entry{}
	for _, e := range ents {
		fp := filepath.Join(abs, e.Name())
		info, _ := e.Info()
		var etag *string
		// ETag/Hash nur für Dateien berechnen, wenn angefordert
		if withEtag && !e.IsDir() {
			h, _, err := fileSHA256(fp)
			if err == nil {
				s := "sha256:" + h
				etag = &s
			}
		}
		pRel, _ := filepath.Rel(s.dataDir, fp)
		out = append(out, entry{
			Name:  e.Name(),
			Path:  filepath.ToSlash(pRel), // plattformneutrale Slashes
			Size:  info.Size(),
			Mtime: info.ModTime().UTC().Format(time.RFC3339),
			IsDir: e.IsDir(),
			Etag:  etag,
		})
	}
	writeJSON(w, 200, map[string]any{"entries": out})
}

// deleteFile: Löscht Datei/Ordner unterhalb DATA_DIR.
// Optional If-Match: erfordert passendes ETag "sha256:<hex>".
func (s *Server) deleteFile(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	if rel == "" {
		http.Error(w, "path required", http.StatusBadRequest)
		return
	}
	abs, err := s.safeJoin(rel, s.dataDir)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	// ETag-Prüfung (If-Match)
	want := r.Header.Get("If-Match")
	if want != "" {
		got, _, err := fileSHA256(abs)
		if err != nil || ("sha256:"+got) != want {
			http.Error(w, "etag mismatch", http.StatusPreconditionFailed)
			return
		}
	}

	if err := os.RemoveAll(abs); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// moveFile: Verschiebt/Renamed eine Datei innerhalb DATA_DIR.
// Optional If-Match Header; Overwrite steuert Zielkollision.
func (s *Server) moveFile(w http.ResponseWriter, r *http.Request) {
	var in struct {
		From, To  string
		Overwrite bool
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.From == "" || in.To == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	src, err := s.safeJoin(in.From, s.dataDir)
	if err != nil {
		http.Error(w, "invalid src", http.StatusBadRequest)
		return
	}
	dst, err := s.safeJoin(in.To, s.dataDir)
	if err != nil {
		http.Error(w, "invalid dst", http.StatusBadRequest)
		return
	}

	// Kollision prüfen, falls Overwrite=false
	if !in.Overwrite {
		if _, err := os.Stat(dst); err == nil {
			http.Error(w, "target exists", http.StatusConflict)
			return
		}
	}

	// If-Match (ETag) prüfen
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		got, _, err := fileSHA256(src)
		if err != nil || ("sha256:"+got) != ifMatch {
			http.Error(w, "etag mismatch", http.StatusPreconditionFailed)
			return
		}
	}

	_ = os.MkdirAll(filepath.Dir(dst), 0755)
	if err := os.Rename(src, dst); err != nil {
		http.Error(w, "move failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	// .bin als octet-stream registrieren (hilfreich für Downloads)
	_ = mime.AddExtensionType(".bin", "application/octet-stream")

	// Server + Router aufsetzen
	s := NewServer()
	r := chi.NewRouter()
	r.Use(s.authMiddleware)

	// Routen
	r.Get("/v1/health", s.health)
	r.Post("/v1/auth/login", s.login)
	r.Post("/v1/uploads", s.postUploads)
	r.Head("/v1/uploads/{id}", s.headUpload)
	r.Patch("/v1/uploads/{id}", s.patchUpload)
	r.Post("/v1/uploads/{id}/commit", s.commitUpload)
	r.Delete("/v1/uploads/{id}", s.deleteUpload)
	r.Get("/v1/files", s.listFiles)
	r.Delete("/v1/files", s.deleteFile)
	r.Post("/v1/files/move", s.moveFile)

	// Start HTTP-Server
	port := envOr("PORT", "8080")
	addr := ":" + port
	log.Printf("AutoSync listening on %s (DATA_DIR=%s)", addr, s.dataDir)
	log.Fatal(http.ListenAndServe(addr, r))
}
