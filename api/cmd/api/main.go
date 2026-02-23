package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	Token       string
	DatabaseURL string
	RedisAddr   string
}

type App struct {
	cfg   Config
	db    *pgxpool.Pool
	redis *redis.Client
}

var errNotFound = errors.New("not found")

func main() {
	cfg := Config{
		Token:       os.Getenv("SSAO_TOKEN"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		RedisAddr:   os.Getenv("REDIS_ADDR"),
	}
	if cfg.Token == "" {
		cfg.Token = "change-me-super-long-random"
	}
	if cfg.DatabaseURL == "" || cfg.RedisAddr == "" {
		log.Fatal("DATABASE_URL and REDIS_ADDR are required")
	}

	ctx := context.Background()

	db, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatal(err)
	}

	app := &App{cfg: cfg, db: db, redis: rdb}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.Logger)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	r.Route("/api", func(r chi.Router) {
		r.Use(app.authz)
		r.Get("/repos", app.listRepos)
		r.Post("/repos", app.createRepo)
		r.Get("/repos/{id}", app.getRepo)
		r.Post("/repos/{id}/scans", app.triggerScan)
		r.Get("/jobs/{id}", app.getJob)
		r.Get("/repos/{id}/findings", app.listFindings)
		r.Post("/repos/{id}/pr-suggestions", app.prSuggestions)
		r.Post("/repos/{id}/pull-requests", app.createPullRequest)
	})

	log.Println("API listening on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}

func (a *App) authz(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+a.cfg.Token {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func badRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
}

func serverError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
}

func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
}
