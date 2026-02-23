package patch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildPlanAllowlist(t *testing.T) {
	findings := []Finding{
		{Tool: "gitleaks", Title: "Secret detected: github-pat", FilePath: "config/app.env", LineStart: 2},
		{Tool: "semgrep", Title: "Potential SQL injection", FilePath: "app/main.go", LineStart: 44},
		{Tool: "trivy", Title: "Weak TLS setting", FilePath: "deploy.yaml", LineStart: 3},
	}
	plan := BuildPlan(findings, 10)
	if len(plan.Actions) == 0 {
		t.Fatal("expected at least one safe action")
	}
	foundSecret := false
	for _, a := range plan.Actions {
		if a.Type == FixSecretRedaction {
			foundSecret = true
		}
	}
	if !foundSecret {
		t.Fatal("expected secret redaction action")
	}
	if len(plan.Manual) == 0 {
		t.Fatal("expected non-allowlisted item to be manual")
	}
}

func TestApplyPlanDryRunPath(t *testing.T) {
	tmp := t.TempDir()
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".gitignore"), []byte("node_modules/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "settings.env"), []byte("API_TOKEN=abc1234567890\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	plan := Plan{Actions: []FixAction{
		{Type: FixGitIgnoreEnv, FilePath: ".gitignore"},
		{Type: FixSecretRedaction, FilePath: "settings.env", LineStart: 1},
	}}
	res, err := ApplyPlan(repo, plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 2 {
		t.Fatalf("expected 2 applied actions, got %d", len(res.Applied))
	}

	b, err := os.ReadFile(filepath.Join(repo, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), ".env") {
		t.Fatal("expected .env to be appended")
	}

	secret, err := os.ReadFile(filepath.Join(repo, "settings.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(secret), "${SECRET_FROM_ENV}") {
		t.Fatal("expected secret placeholder replacement")
	}
}
