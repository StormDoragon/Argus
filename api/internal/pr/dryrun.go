package pr

import "argus/api/internal/patch"

func GenerateDryRunDiff(repoDir string, findings []patch.Finding, maxFixes int) (string, patch.Plan, patch.ApplyResult, error) {
	plan := patch.BuildPlan(findings, maxFixes)
	applied, err := patch.ApplyPlan(repoDir, plan)
	if err != nil {
		return "", plan, applied, err
	}
	d, err := patch.LoadDiff(repoDir)
	if err != nil {
		return "", plan, applied, err
	}
	return d, plan, applied, nil
}
