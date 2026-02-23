package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"argus/api/internal/pr"

	"github.com/go-chi/chi/v5"
)

type createPRReq struct {
	Title      string `json:"title"`
	BaseBranch string `json:"base_branch"`
	Confirm    bool   `json:"confirm"`
	MaxFixes   int    `json:"max_fixes"`
}

func (a *App) createPullRequest(w http.ResponseWriter, r *http.Request) {
	repoID := chi.URLParam(r, "id")
	var req createPRReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "invalid json")
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		req.Title = "Argus: Fix findings"
	}
	if req.MaxFixes <= 0 {
		req.MaxFixes = 10
	}

	svc := pr.NewService(a.db)
	res, err := svc.Create(r.Context(), pr.Request{
		RepoID:      repoID,
		Title:       req.Title,
		BaseBranch:  req.BaseBranch,
		Confirm:     req.Confirm,
		MaxFixes:    req.MaxFixes,
		RequestedBy: r.Header.Get("Authorization"),
	})
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
