package pr

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"argus/api/internal/githubapp"
	"argus/api/internal/patch"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	db *pgxpool.Pool
}

func NewService(db *pgxpool.Pool) *Service { return &Service{db: db} }

type Request struct {
	RepoID      string
	Title       string
	BaseBranch  string
	Confirm     bool
	MaxFixes    int
	RequestedBy string
}

type Response struct {
	Mode   string `json:"mode"`
	Diff   string `json:"diff"`
	PRURL  string `json:"pr_url,omitempty"`
	Branch string `json:"branch,omitempty"`
}

type repoRow struct {
	URL string
}

func (s *Service) Create(ctx context.Context, req Request) (Response, error) {
	var repo repoRow
	if err := s.db.QueryRow(ctx, `SELECT url FROM repos WHERE id=$1`, req.RepoID).Scan(&repo.URL); err != nil {
		return Response{}, fmt.Errorf("repo not found")
	}
	if !strings.HasPrefix(strings.ToLower(repo.URL), "https://github.com/") || !strings.HasSuffix(strings.ToLower(repo.URL), ".git") {
		return Response{}, fmt.Errorf("only github.com .git repos are supported")
	}

	findings, err := s.loadFindings(ctx, req.RepoID, req.MaxFixes)
	if err != nil {
		return Response{}, err
	}
	workDir := filepath.Join(os.TempDir(), "argus-pr", fmt.Sprintf("%d", time.Now().UnixNano()))
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return Response{}, err
	}
	defer os.RemoveAll(workDir)

	repoDir := filepath.Join(workDir, "repo")
	cloneCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if err := cloneRepo(cloneCtx, repo.URL, repoDir); err != nil {
		return Response{}, err
	}
	if err := enforceSizeCap(repoDir, 350); err != nil {
		return Response{}, err
	}

	diffText, plan, _, err := GenerateDryRunDiff(repoDir, findings, req.MaxFixes)
	if err != nil {
		return Response{}, err
	}
	if strings.TrimSpace(diffText) == "" {
		diffText = "# No safe automatic changes available\n"
	}

	mode := "dry-run"
	prURL := ""
	branch := ""
	if req.Confirm {
		gh, err := githubapp.NewFromEnv()
		if err != nil {
			return Response{}, err
		}
		if err := githubapp.ValidateGitHubAppIDs(os.Getenv("GITHUB_APP_ID"), os.Getenv("GITHUB_INSTALLATION_ID")); err != nil {
			return Response{}, err
		}
		token, err := gh.InstallationToken()
		if err != nil {
			return Response{}, err
		}
		owner, repoName, err := githubapp.ParseGitHubURL(repo.URL)
		if err != nil {
			return Response{}, err
		}
		base := strings.TrimSpace(req.BaseBranch)
		if base == "" {
			base, err = gh.GetDefaultBranch(owner, repoName, token)
			if err != nil {
				return Response{}, err
			}
		}
		sha, err := gh.GetBranchSHA(owner, repoName, base, token)
		if err != nil {
			return Response{}, err
		}
		branch = fmt.Sprintf("argus/fix-%d", time.Now().Unix())
		if err := gh.CreateRef(owner, repoName, "refs/heads/"+branch, sha, token); err != nil {
			return Response{}, err
		}

		if err := commitAndPush(ctx, repoDir, repo.URL, branch, token); err != nil {
			return Response{}, err
		}

		body := buildPRBody(diffText, plan.Manual)
		title := req.Title
		if strings.TrimSpace(title) == "" {
			title = "Argus: Fix findings"
		}
		prURL, err = gh.CreatePullRequest(owner, repoName, title, branch, base, body, token)
		if err != nil {
			return Response{}, err
		}
		mode = "created"
	}

	if err := s.recordPR(ctx, req, mode, branch, prURL, diffText); err != nil {
		return Response{}, err
	}

	return Response{Mode: mode, Diff: diffText, PRURL: prURL, Branch: branch}, nil
}

func (s *Service) loadFindings(ctx context.Context, repoID string, max int) ([]patch.Finding, error) {
	if max <= 0 {
		max = 10
	}
	rows, err := s.db.Query(ctx, `SELECT tool::text, title, COALESCE(file_path,''), COALESCE(line_start,0) FROM findings WHERE repo_id=$1 ORDER BY created_at DESC LIMIT $2`, repoID, max)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]patch.Finding, 0)
	for rows.Next() {
		var f patch.Finding
		if err := rows.Scan(&f.Tool, &f.Title, &f.FilePath, &f.LineStart); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		out = append(out, patch.Finding{Tool: "policy", Title: "Ensure .env ignored", FilePath: ".gitignore"})
	}
	return out, nil
}

func (s *Service) recordPR(ctx context.Context, req Request, status, branch, prURL, diffText string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO prs (repo_id, job_id, status, branch, pr_url, diff_text) VALUES ($1, NULL, $2, $3, $4, $5)`, req.RepoID, status, nullIfEmpty(branch), nullIfEmpty(prURL), diffText)
	return err
}

func nullIfEmpty(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func cloneRepo(ctx context.Context, repoURL, repoDir string) error {
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--filter=blob:none", "--no-tags", repoURL, repoDir)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %w: %s", err, string(out))
	}
	return nil
}

func enforceSizeCap(repoDir string, maxMB int) error {
	var size int64
	err := filepath.Walk(repoDir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.Mode().IsRegular() {
			size += info.Size()
		}
		return nil
	})
	if err != nil {
		return err
	}
	if size > int64(maxMB)*1024*1024 {
		return fmt.Errorf("repo exceeds size cap")
	}
	return nil
}

func commitAndPush(ctx context.Context, repoDir, repoURL, branch, token string) error {
	authURL := strings.Replace(repoURL, "https://", "https://x-access-token:"+token+"@", 1)
	cmds := [][]string{
		{"git", "-C", repoDir, "checkout", "-b", branch},
		{"git", "-C", repoDir, "config", "user.email", "argus[bot]@users.noreply.github.com"},
		{"git", "-C", repoDir, "config", "user.name", "argus[bot]"},
		{"git", "-C", repoDir, "add", "-A"},
		{"git", "-C", repoDir, "commit", "-m", "Argus: apply safe automatic fixes"},
		{"git", "-C", repoDir, "push", authURL, "HEAD:" + branch},
	}
	for _, args := range cmds {
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		out, err := cmd.CombinedOutput()
		if err != nil {
			if strings.Contains(string(out), "nothing to commit") {
				continue
			}
			return fmt.Errorf("git command failed")
		}
	}
	return nil
}

func buildPRBody(diff string, manual []patch.ManualItem) string {
	manualText := ""
	if len(manual) > 0 {
		b, _ := json.MarshalIndent(manual, "", "  ")
		manualText = "\n\n## Manual items\n```json\n" + string(b) + "\n```"
	}
	if len(diff) > 8000 {
		diff = diff[:8000] + "\n... (truncated)"
	}
	return "Automated safe fixes generated by Argus." + manualText + "\n\n## Diff preview\n```diff\n" + diff + "\n```"
}
