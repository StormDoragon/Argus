package pr

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"argus/api/internal/patch"
)

func TestGenerateDryRunDiff_NoGitHubCredsRequired(t *testing.T) {
	repo := t.TempDir()
	must(t, exec.Command("git", "-C", repo, "init").Run())
	must(t, os.WriteFile(filepath.Join(repo, ".gitignore"), []byte("node_modules/\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(repo, "app.env"), []byte("API_TOKEN='supersecretvalue'\n"), 0o644))
	must(t, exec.Command("git", "-C", repo, "add", ".").Run())
	must(t, exec.Command("git", "-C", repo, "-c", "user.email=test@example.com", "-c", "user.name=test", "commit", "-m", "init").Run())

	findings := []patch.Finding{{Tool: "gitleaks", Title: "Secret detected", FilePath: "app.env", LineStart: 1}}
	diff, _, _, err := GenerateDryRunDiff(repo, findings, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, "SECRET_FROM_ENV") {
		t.Fatalf("expected diff to include redaction placeholder, got: %s", diff)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
