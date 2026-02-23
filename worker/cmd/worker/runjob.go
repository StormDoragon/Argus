package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

type RepoRow struct {
	URL  string
	Name string
}

func runJob(ctx context.Context, db *pgxpool.Pool, msg JobMsg, maxCloneMB int) error {
	if _, err := db.Exec(ctx, `UPDATE jobs SET status='running', started_at=now(), error=NULL WHERE id=$1`, msg.JobID); err != nil {
		return err
	}

	var repo RepoRow
	err := db.QueryRow(ctx, `SELECT url, name FROM repos WHERE id=$1`, msg.RepoID).Scan(&repo.URL, &repo.Name)
	if err != nil {
		_ = failJob(ctx, db, msg.JobID, "repo not found")
		return err
	}
	if !isSafeRepoURL(repo.URL) {
		_ = failJob(ctx, db, msg.JobID, "repo url rejected by policy")
		return errors.New("repo url rejected by policy")
	}

	workRoot := filepath.Join(os.TempDir(), "argus", msg.JobID)
	_ = os.RemoveAll(workRoot)
	if err := os.MkdirAll(workRoot, 0o755); err != nil {
		_ = failJob(ctx, db, msg.JobID, "cannot create workdir")
		return err
	}
	defer os.RemoveAll(workRoot)

	repoDir := filepath.Join(workRoot, "repo")
	if err := safeClone(ctx, repo.URL, repoDir, maxCloneMB); err != nil {
		_ = failJob(ctx, db, msg.JobID, "clone failed: "+err.Error())
		return err
	}

	if err := runSemgrep(ctx, db, msg, repoDir); err != nil {
		fmt.Println("semgrep error:", err)
	}
	if err := runGitleaks(ctx, db, msg, repoDir); err != nil {
		fmt.Println("gitleaks error:", err)
	}
	if err := runTrivy(ctx, db, msg, repoDir); err != nil {
		fmt.Println("trivy error:", err)
	}

	if _, err := db.Exec(ctx, `UPDATE jobs SET status='succeeded', finished_at=now() WHERE id=$1`, msg.JobID); err != nil {
		return err
	}
	return nil
}

func failJob(ctx context.Context, db *pgxpool.Pool, jobID string, e string) error {
	_, err := db.Exec(ctx, `UPDATE jobs SET status='failed', finished_at=now(), error=$2 WHERE id=$1`, jobID, e)
	return err
}

func isSafeRepoURL(raw string) bool {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if !strings.HasPrefix(raw, "https://") || !strings.HasSuffix(raw, ".git") {
		return false
	}
	return strings.HasPrefix(raw, "https://github.com/")
}

func safeClone(ctx context.Context, repoURL, repoDir string, maxCloneMB int) error {
	token := strings.TrimSpace(os.Getenv("GIT_TOKEN"))
	cloneURL := repoURL
	if token != "" {
		cloneURL = strings.Replace(repoURL, "https://", "https://x-access-token:"+token+"@", 1)
	}

	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--filter=blob:none", "--no-tags", cloneURL, repoDir)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone: %v: %s", err, string(out))
	}

	var sizeBytes int64
	_ = filepath.Walk(repoDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil {
			return nil
		}
		if info.Mode().IsRegular() {
			sizeBytes += info.Size()
		}
		return nil
	})

	if sizeBytes > int64(maxCloneMB)*1024*1024 {
		return fmt.Errorf("repo exceeds size limit (%d MB)", maxCloneMB)
	}
	return nil
}

func insertFinding(ctx context.Context, db *pgxpool.Pool, repoID, jobID, tool, severity, title string, filePath *string, lineStart, lineEnd *int, fingerprint *string, desc *string, evidence any) error {
	ev, _ := json.Marshal(evidence)
	_, err := db.Exec(ctx, `INSERT INTO findings (repo_id, job_id, tool, severity, title, file_path, line_start, line_end, fingerprint, description, evidence_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		repoID, jobID, tool, severity, title, filePath, lineStart, lineEnd, fingerprint, desc, ev)
	return err
}

func fp(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func runCmdJSON(ctx context.Context, name string, args []string, workdir string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = workdir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %v: %v: %s", name, args, err, string(out))
	}
	return out, nil
}
