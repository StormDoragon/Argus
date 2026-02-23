package patch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type Finding struct {
	Tool      string
	Title     string
	FilePath  string
	LineStart int
}

type FixActionType string

const (
	FixSecretRedaction FixActionType = "secret_redaction"
	FixGitIgnoreEnv    FixActionType = "gitignore_env"
)

type FixAction struct {
	Type        FixActionType
	FilePath    string
	LineStart   int
	Description string
}

type ManualItem struct {
	Reason string `json:"reason"`
	Title  string `json:"title"`
	File   string `json:"file"`
}

type Plan struct {
	Actions []FixAction
	Manual  []ManualItem
}

func BuildPlan(findings []Finding, maxFixes int) Plan {
	if maxFixes <= 0 {
		maxFixes = 10
	}
	plan := Plan{Actions: make([]FixAction, 0), Manual: make([]ManualItem, 0)}
	seenGitignore := false

	for _, f := range findings {
		if len(plan.Actions) >= maxFixes {
			break
		}
		filePath := filepath.ToSlash(strings.TrimSpace(f.FilePath))
		title := strings.ToLower(strings.TrimSpace(f.Title))
		tool := strings.ToLower(strings.TrimSpace(f.Tool))

		if (tool == "gitleaks" || strings.Contains(title, "secret")) && filePath != "" {
			plan.Actions = append(plan.Actions, FixAction{
				Type:        FixSecretRedaction,
				FilePath:    filePath,
				LineStart:   f.LineStart,
				Description: "Replace hardcoded credential-like value with environment placeholder",
			})
			continue
		}

		if !seenGitignore {
			plan.Actions = append(plan.Actions, FixAction{
				Type:        FixGitIgnoreEnv,
				FilePath:    ".gitignore",
				Description: "Ensure .env is ignored",
			})
			seenGitignore = true
			continue
		}

		plan.Manual = append(plan.Manual, ManualItem{
			Reason: "manual fix required: ambiguous or potentially unsafe automatic change",
			Title:  f.Title,
			File:   f.FilePath,
		})
	}

	if !seenGitignore && len(plan.Actions) < maxFixes {
		plan.Actions = append(plan.Actions, FixAction{
			Type:        FixGitIgnoreEnv,
			FilePath:    ".gitignore",
			Description: "Ensure .env is ignored",
		})
	}

	return plan
}

type ApplyResult struct {
	Applied []FixAction
	Manual  []ManualItem
}

var secretAssignPattern = regexp.MustCompile(`(?i)^([ \t]*[A-Z0-9_\-\.]*?(token|secret|password|apikey|api_key)[A-Z0-9_\-\.]*(?:[ \t]*[:=][ \t]*|[ \t]+))("[^"]*"|'[^']*'|[A-Za-z0-9_\-]{12,})(.*)$`)

func ApplyPlan(repoDir string, plan Plan) (ApplyResult, error) {
	result := ApplyResult{Applied: make([]FixAction, 0), Manual: append([]ManualItem{}, plan.Manual...)}
	root := filepath.Clean(repoDir)

	for _, action := range plan.Actions {
		switch action.Type {
		case FixGitIgnoreEnv:
			applied, err := ensureEnvIgnored(filepath.Join(root, ".gitignore"))
			if err != nil {
				return result, err
			}
			if applied {
				result.Applied = append(result.Applied, action)
			}
		case FixSecretRedaction:
			rel := filepath.Clean(action.FilePath)
			target := filepath.Join(root, rel)
			if !strings.HasPrefix(target, root+string(os.PathSeparator)) && target != root {
				result.Manual = append(result.Manual, ManualItem{Reason: "manual fix required: invalid target path", Title: action.Description, File: action.FilePath})
				continue
			}
			applied, err := redactSecretLine(target, action.LineStart)
			if err != nil {
				return result, err
			}
			if applied {
				result.Applied = append(result.Applied, action)
			} else {
				result.Manual = append(result.Manual, ManualItem{Reason: "manual fix required: no safe redaction match found", Title: action.Description, File: action.FilePath})
			}
		default:
			result.Manual = append(result.Manual, ManualItem{Reason: "manual fix required: unsupported action", Title: action.Description, File: action.FilePath})
		}
	}

	return result, nil
}

func ensureEnvIgnored(path string) (bool, error) {
	s := ""
	if b, err := os.ReadFile(path); err == nil {
		s = string(b)
	} else if !os.IsNotExist(err) {
		return false, err
	}

	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(l) == ".env" {
			return false, nil
		}
	}
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	s += ".env\n"
	return true, os.WriteFile(path, []byte(s), 0o644)
}

func redactSecretLine(path string, lineStart int) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	if lineStart > 0 && lineStart <= len(lines) {
		if repl, ok := redactLine(lines[lineStart-1]); ok {
			lines[lineStart-1] = repl
			return true, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
		}
	}
	for i, line := range lines {
		if repl, ok := redactLine(line); ok {
			lines[i] = repl
			return true, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
		}
	}
	return false, nil
}

func redactLine(line string) (string, bool) {
	m := secretAssignPattern.FindStringSubmatch(line)
	if len(m) == 0 {
		return "", false
	}
	return fmt.Sprintf("%s\"${SECRET_FROM_ENV}\"%s", m[1], m[4]), true
}

func LoadDiff(repoDir string) (string, error) {
	cmd := exec.Command("git", "-C", repoDir, "diff", "--", ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git diff failed: %w: %s", err, string(out))
	}
	return string(out), nil
}
