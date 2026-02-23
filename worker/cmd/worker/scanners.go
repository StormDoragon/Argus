package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

type semgrepOut struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		Extra struct {
			Message  string         `json:"message"`
			Severity string         `json:"severity"`
			Metadata map[string]any `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

func runSemgrep(ctx context.Context, db *pgxpool.Pool, msg JobMsg, repoDir string) error {
	out, err := runCmdJSON(ctx, "semgrep", []string{"scan", "--config", "auto", "--json", "--quiet", "--timeout", "120", "."}, repoDir)
	var parsed semgrepOut
	if perr := json.Unmarshal(out, &parsed); perr != nil {
		if err != nil {
			return err
		}
		return fmt.Errorf("semgrep parse error: %v", perr)
	}

	for _, r := range parsed.Results {
		sev := strings.ToUpper(strings.TrimSpace(r.Extra.Severity))
		if sev == "" {
			sev = "MEDIUM"
		}
		title := r.CheckID
		desc := r.Extra.Message
		fpv := fp("semgrep", r.CheckID, r.Path, fmt.Sprintf("%d", r.Start.Line), desc)
		filePath := r.Path
		ls, le := r.Start.Line, r.End.Line
		_ = insertFinding(ctx, db, msg.RepoID, msg.JobID, "semgrep", sev, title, &filePath, &ls, &le, &fpv, &desc, map[string]any{
			"check_id": r.CheckID,
			"metadata": r.Extra.Metadata,
		})
	}
	return err
}

type gitleaksOut []struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
	Severity    string `json:"Severity"`
}

func runGitleaks(ctx context.Context, db *pgxpool.Pool, msg JobMsg, repoDir string) error {
	out, err := runCmdJSON(ctx, "gitleaks", []string{"detect", "--source", ".", "--no-git", "--report-format", "json", "--redact"}, repoDir)
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return err
	}

	var parsed gitleaksOut
	if perr := json.Unmarshal([]byte(raw), &parsed); perr != nil {
		if err != nil {
			return err
		}
		return fmt.Errorf("gitleaks parse error: %v", perr)
	}

	for _, f := range parsed {
		sev := strings.ToUpper(strings.TrimSpace(f.Severity))
		if sev == "" {
			sev = "HIGH"
		}
		title := "Secret detected: " + f.RuleID
		desc := f.Description
		fpv := fp("gitleaks", f.RuleID, f.File, fmt.Sprintf("%d", f.StartLine))
		filePath := f.File
		ls, le := f.StartLine, f.EndLine
		_ = insertFinding(ctx, db, msg.RepoID, msg.JobID, "gitleaks", sev, title, &filePath, &ls, &le, &fpv, &desc, map[string]any{
			"rule_id":  f.RuleID,
			"redacted": true,
		})
	}
	return err
}

type trivyOut struct {
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			Description      string `json:"Description"`
			PrimaryURL       string `json:"PrimaryURL"`
		} `json:"Vulnerabilities"`
		Misconfigurations []struct {
			ID            string `json:"ID"`
			Title         string `json:"Title"`
			Description   string `json:"Description"`
			Severity      string `json:"Severity"`
			PrimaryURL    string `json:"PrimaryURL"`
			CauseMetadata struct {
				Resource  string `json:"Resource"`
				Provider  string `json:"Provider"`
				Service   string `json:"Service"`
				StartLine int    `json:"StartLine"`
				EndLine   int    `json:"EndLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
	} `json:"Results"`
}

func runTrivy(ctx context.Context, db *pgxpool.Pool, msg JobMsg, repoDir string) error {
	out, err := runCmdJSON(ctx, "trivy", []string{"fs", "--format", "json", "--quiet", "--scanners", "vuln,misconfig,secret", "--timeout", "8m", "."}, repoDir)
	var parsed trivyOut
	if perr := json.Unmarshal(out, &parsed); perr != nil {
		if err != nil {
			return err
		}
		return fmt.Errorf("trivy parse error: %v", perr)
	}

	for _, r := range parsed.Results {
		for _, v := range r.Vulnerabilities {
			sev := strings.ToUpper(strings.TrimSpace(v.Severity))
			if sev == "" {
				sev = "MEDIUM"
			}
			title := v.VulnerabilityID + " in " + v.PkgName
			desc := v.Title
			if desc == "" {
				desc = v.Description
			}
			fpv := fp("trivy:vuln", v.VulnerabilityID, v.PkgName, v.InstalledVersion, r.Target)
			target := filepath.ToSlash(r.Target)
			_ = insertFinding(ctx, db, msg.RepoID, msg.JobID, "trivy", sev, title, &target, nil, nil, &fpv, &desc, map[string]any{
				"pkg":       v.PkgName,
				"installed": v.InstalledVersion,
				"fixed":     v.FixedVersion,
				"url":       v.PrimaryURL,
				"class":     r.Class,
				"type":      r.Type,
			})
		}

		for _, m := range r.Misconfigurations {
			sev := strings.ToUpper(strings.TrimSpace(m.Severity))
			if sev == "" {
				sev = "MEDIUM"
			}
			title := m.ID + ": " + m.Title
			desc := m.Description
			fpv := fp("trivy:misconfig", m.ID, r.Target, fmt.Sprintf("%d", m.CauseMetadata.StartLine))
			target := filepath.ToSlash(r.Target)
			ls, le := m.CauseMetadata.StartLine, m.CauseMetadata.EndLine
			_ = insertFinding(ctx, db, msg.RepoID, msg.JobID, "trivy", sev, title, &target, &ls, &le, &fpv, &desc, map[string]any{
				"id":       m.ID,
				"url":      m.PrimaryURL,
				"resource": m.CauseMetadata.Resource,
				"provider": m.CauseMetadata.Provider,
				"service":  m.CauseMetadata.Service,
			})
		}
	}
	return err
}
