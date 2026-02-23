# Argus

**Autonomous Repository Guardian & Security**

Argus is a self-hosted, scope-locked security assessment orchestrator for Git repositories. Inspired by Argus Panoptes—the many-eyed guardian of Greek mythology—Argus continuously watches your codebase for vulnerable patterns, exposed secrets, and risky dependency or configuration states while keeping operations constrained and auditable.

Built for defensive security teams, DevSecOps programs, and independent maintainers, Argus focuses on practical repository scanning with explicit safety boundaries. Repositories must be registered before scans can run, scanner jobs are executed in an isolated worker container, and findings are stored with structured evidence for triage and follow-up remediation.

Argus combines three safe-by-default tools:
- **Semgrep** for static code analysis
- **Gitleaks** for secret detection
- **Trivy (filesystem mode)** for dependency and misconfiguration assessment

The system is composed of a Go API, a Go worker, Redis queueing, PostgreSQL + pgvector storage, and a React + Vite web interface. Findings include metadata such as severity, source tool, file/line context, evidence JSON, and fingerprints to support deduplication in future iterations.

Security controls are built in from the start: URL policy checks (GitHub HTTPS `.git` only), shallow clone strategy, repository size limits, and per-job timeout enforcement. Private repositories are supported through read-only tokens used only during clone operations.

Argus also includes PR suggestions and **real PR creation** behind an approval gate:
- `confirm=false` (default) creates a dry-run diff preview only.
- `confirm=true` creates a branch, pushes safe edits, and opens a pull request via GitHub App installation auth.

Argus does not exploit. It guards.
Argus does not attack. It illuminates.

## Quickstart

```bash
cp .env.example .env
docker compose up --build
```

Open:
- UI: http://localhost:3000
- API health: http://localhost:8080/healthz

## GitHub App setup (least privilege)

Set these in `.env`:

```bash
GITHUB_APP_ID=
GITHUB_INSTALLATION_ID=
GITHUB_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
```

Required GitHub App repository permissions:
- **Metadata: Read-only**
- **Contents: Read & write**
- **Pull requests: Read & write**

Recommended protections:
- Enable branch protections on default branches.
- Require pull request review before merge.
- Keep Argus PR creation on `confirm=true` only for approved runs.

## Pull request API

`POST /api/repos/{id}/pull-requests`

Body:

```json
{
  "title": "Argus: Fix findings",
  "base_branch": "",
  "confirm": false,
  "max_fixes": 10
}
```

Response:

```json
{
  "mode": "dry-run",
  "diff": "...",
  "pr_url": "",
  "branch": ""
}
```

## Basic usage

```bash
export SSAO_TOKEN="change-me-super-long-random"

curl -sS -X POST http://localhost:8080/api/repos \
  -H "Authorization: Bearer $SSAO_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-repo","url":"https://github.com/org/repo.git"}'

curl -sS -X POST http://localhost:8080/api/repos/<REPO_ID>/scans \
  -H "Authorization: Bearer $SSAO_TOKEN"

curl -sS -X POST http://localhost:8080/api/repos/<REPO_ID>/pull-requests \
  -H "Authorization: Bearer $SSAO_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Argus: Fix findings","confirm":false,"max_fixes":10}'
```


## Restricted-network builds

If your CI/host cannot reach Go module mirrors or GitHub, use vendoring from an unrestricted machine and then build in vendor mode.

- Full guide: `VENDORING.md`
- Quick check script: `scripts/check_vendor_state.sh`

Example restricted-host commands:

```bash
cd api && go test -mod=vendor ./...
cd ../worker && go test -mod=vendor ./...
```
