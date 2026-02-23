package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

type Repo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	CreatedAt time.Time `json:"created_at"`
}

type createRepoReq struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Job struct {
	ID         string     `json:"id"`
	RepoID     string     `json:"repo_id"`
	Status     string     `json:"status"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Error      *string    `json:"error,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type Finding struct {
	ID          string          `json:"id"`
	Tool        string          `json:"tool"`
	Severity    string          `json:"severity"`
	Title       string          `json:"title"`
	FilePath    *string         `json:"file_path,omitempty"`
	LineStart   *int            `json:"line_start,omitempty"`
	LineEnd     *int            `json:"line_end,omitempty"`
	Fingerprint *string         `json:"fingerprint,omitempty"`
	Description *string         `json:"description,omitempty"`
	Evidence    json.RawMessage `json:"evidence_json,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
}

func (a *App) listRepos(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(r.Context(), `SELECT id::text, name, url, created_at FROM repos ORDER BY created_at DESC`)
	if err != nil {
		serverError(w, err)
		return
	}
	defer rows.Close()

	out := make([]Repo, 0)
	for rows.Next() {
		var rp Repo
		if err := rows.Scan(&rp.ID, &rp.Name, &rp.URL, &rp.CreatedAt); err != nil {
			serverError(w, err)
			return
		}
		out = append(out, rp)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) createRepo(w http.ResponseWriter, r *http.Request) {
	var req createRepoReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "invalid json")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.URL = strings.TrimSpace(req.URL)
	if req.Name == "" || req.URL == "" {
		badRequest(w, "name and url are required")
		return
	}
	if !isAllowedGitURL(req.URL) {
		badRequest(w, "url must be https://.../.git and non-localhost")
		return
	}

	var id string
	err := a.db.QueryRow(r.Context(), `INSERT INTO repos (name, url) VALUES ($1,$2) RETURNING id::text`, req.Name, req.URL).Scan(&id)
	if err != nil {
		serverError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (a *App) getRepo(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var rp Repo
	err := a.db.QueryRow(r.Context(), `SELECT id::text, name, url, created_at FROM repos WHERE id=$1`, id).
		Scan(&rp.ID, &rp.Name, &rp.URL, &rp.CreatedAt)
	if err != nil {
		notFound(w)
		return
	}
	writeJSON(w, http.StatusOK, rp)
}

func (a *App) triggerScan(w http.ResponseWriter, r *http.Request) {
	repoID := chi.URLParam(r, "id")

	var exists bool
	if err := a.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM repos WHERE id=$1)`, repoID).Scan(&exists); err != nil {
		serverError(w, err)
		return
	}
	if !exists {
		notFound(w)
		return
	}

	var jobID string
	if err := a.db.QueryRow(r.Context(), `INSERT INTO jobs (repo_id, status) VALUES ($1,'queued') RETURNING id::text`, repoID).Scan(&jobID); err != nil {
		serverError(w, err)
		return
	}

	payload, _ := json.Marshal(map[string]string{"job_id": jobID, "repo_id": repoID})
	if err := a.redis.LPush(r.Context(), "ssao:jobs", payload).Err(); err != nil {
		serverError(w, err)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": jobID})
}

func (a *App) getJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var jb Job
	err := a.db.QueryRow(r.Context(), `SELECT id::text, repo_id::text, status::text, started_at, finished_at, error, created_at FROM jobs WHERE id=$1`, id).
		Scan(&jb.ID, &jb.RepoID, &jb.Status, &jb.StartedAt, &jb.FinishedAt, &jb.Error, &jb.CreatedAt)
	if err != nil {
		notFound(w)
		return
	}
	writeJSON(w, http.StatusOK, jb)
}

func (a *App) listFindings(w http.ResponseWriter, r *http.Request) {
	repoID := chi.URLParam(r, "id")
	rows, err := a.db.Query(r.Context(), `SELECT id::text, tool::text, severity, title, file_path, line_start, line_end, fingerprint, description, evidence_json, created_at FROM findings WHERE repo_id=$1 ORDER BY created_at DESC LIMIT 500`, repoID)
	if err != nil {
		serverError(w, err)
		return
	}
	defer rows.Close()

	out := make([]Finding, 0)
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.Tool, &f.Severity, &f.Title, &f.FilePath, &f.LineStart, &f.LineEnd, &f.Fingerprint, &f.Description, &f.Evidence, &f.CreatedAt); err != nil {
			serverError(w, err)
			return
		}
		out = append(out, f)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) prSuggestions(w http.ResponseWriter, r *http.Request) {
	repoID := chi.URLParam(r, "id")
	rows, err := a.db.Query(r.Context(), `SELECT tool::text, severity, title, COALESCE(file_path,''), COALESCE(description,'') FROM findings WHERE repo_id=$1 ORDER BY created_at DESC LIMIT 20`, repoID)
	if err != nil {
		serverError(w, err)
		return
	}
	defer rows.Close()

	type Item struct {
		Tool         string `json:"tool"`
		Severity     string `json:"severity"`
		Title        string `json:"title"`
		File         string `json:"file"`
		Note         string `json:"note"`
		SuggestedFix string `json:"suggested_fix"`
	}

	out := make([]Item, 0)
	for rows.Next() {
		var tool, sev, title, file, note string
		if err := rows.Scan(&tool, &sev, &title, &file, &note); err != nil {
			serverError(w, err)
			return
		}
		out = append(out, Item{
			Tool:         tool,
			Severity:     sev,
			Title:        title,
			File:         file,
			Note:         note,
			SuggestedFix: "Create a targeted code change addressing this finding (manual review required).",
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"repo_id":   repoID,
		"mode":      "suggestions_only",
		"items":     out,
		"next_step": "Wire a GitHub App/PAT with least privilege to open PRs in api/internal/pr/",
	})
}

func isAllowedGitURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return false
	}
	if !strings.HasSuffix(strings.ToLower(u.Path), ".git") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host != "github.com" {
		return false
	}
	return true
}

func formatErr(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", prefix, err)
}
