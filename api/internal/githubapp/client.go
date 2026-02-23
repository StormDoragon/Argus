package githubapp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppID          string
	InstallationID string
	PrivateKeyPEM  string
}

type Client struct {
	httpClient *http.Client
	cfg        Config
	baseURL    string
}

func NewFromEnv() (*Client, error) {
	cfg := Config{
		AppID:          strings.TrimSpace(os.Getenv("GITHUB_APP_ID")),
		InstallationID: strings.TrimSpace(os.Getenv("GITHUB_INSTALLATION_ID")),
		PrivateKeyPEM:  os.Getenv("GITHUB_PRIVATE_KEY_PEM"),
	}
	if cfg.AppID == "" || cfg.InstallationID == "" || strings.TrimSpace(cfg.PrivateKeyPEM) == "" {
		return nil, fmt.Errorf("missing github app env vars")
	}
	return &Client{
		httpClient: &http.Client{Timeout: 25 * time.Second},
		cfg:        cfg,
		baseURL:    "https://api.github.com",
	}, nil
}

func (c *Client) InstallationToken() (string, error) {
	jwtToken, err := c.appJWT()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/app/installations/%s/access_tokens", c.baseURL, c.cfg.InstallationID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("token exchange failed: status=%d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("empty installation token")
	}
	return out.Token, nil
}

func (c *Client) GetDefaultBranch(owner, repo, token string) (string, error) {
	var out struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := c.getJSON(fmt.Sprintf("/repos/%s/%s", owner, repo), token, &out); err != nil {
		return "", err
	}
	if out.DefaultBranch == "" {
		return "", fmt.Errorf("default branch missing")
	}
	return out.DefaultBranch, nil
}

func (c *Client) GetBranchSHA(owner, repo, branch, token string) (string, error) {
	var out struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := c.getJSON(fmt.Sprintf("/repos/%s/%s/git/ref/heads/%s", owner, repo, branch), token, &out); err != nil {
		return "", err
	}
	if out.Object.SHA == "" {
		return "", fmt.Errorf("branch SHA missing")
	}
	return out.Object.SHA, nil
}

func (c *Client) CreateRef(owner, repo, ref, sha, token string) error {
	payload := map[string]string{"ref": ref, "sha": sha}
	return c.postJSON(fmt.Sprintf("/repos/%s/%s/git/refs", owner, repo), token, payload, nil)
}

func (c *Client) CreateOrUpdateContent(owner, repo, path, message, contentB64, branch, token string) error {
	payload := map[string]string{
		"message": message,
		"content": contentB64,
		"branch":  branch,
	}
	return c.putJSON(fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, path), token, payload, nil)
}

func (c *Client) CreatePullRequest(owner, repo, title, head, base, body, token string) (string, error) {
	payload := map[string]string{"title": title, "head": head, "base": base, "body": body}
	var out struct {
		HTMLURL string `json:"html_url"`
	}
	if err := c.postJSON(fmt.Sprintf("/repos/%s/%s/pulls", owner, repo), token, payload, &out); err != nil {
		return "", err
	}
	return out.HTMLURL, nil
}

func (c *Client) CreateIssueComment(owner, repo string, number int, comment, token string) error {
	payload := map[string]string{"body": comment}
	return c.postJSON(fmt.Sprintf("/repos/%s/%s/issues/%d/comments", owner, repo, number), token, payload, nil)
}

func (c *Client) appJWT() (string, error) {
	block, _ := pem.Decode([]byte(c.cfg.PrivateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("invalid private key pem")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		pkcs8, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return "", err
		}
		k, ok := pkcs8.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("private key is not RSA")
		}
		key = k
	}

	now := time.Now().Unix()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := fmt.Sprintf(`{"iat":%d,"exp":%d,"iss":"%s"}`, now-30, now+540, c.cfg.AppID)
	payloadEnc := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := header + "." + payloadEnc
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (c *Client) getJSON(path, token string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, token, out)
}

func (c *Client) postJSON(path, token string, payload, out any) error {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	return c.do(req, token, out)
}

func (c *Client) putJSON(path, token string, payload, out any) error {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPut, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	return c.do(req, token, out)
}

func (c *Client) do(req *http.Request, token string, out any) error {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("github api call failed status=%d", resp.StatusCode)
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return err
		}
	}
	return nil
}

func ParseGitHubURL(raw string) (owner, repo string, err error) {
	u := strings.TrimSpace(raw)
	u = strings.TrimPrefix(u, "https://github.com/")
	parts := strings.Split(u, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid github url")
	}
	owner = strings.TrimSpace(parts[0])
	repo = strings.TrimSuffix(strings.TrimSpace(parts[1]), ".git")
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("invalid github url")
	}
	return owner, repo, nil
}

func ValidateGitHubAppIDs(appID, installationID string) error {
	if _, err := strconv.ParseInt(appID, 10, 64); err != nil {
		return fmt.Errorf("GITHUB_APP_ID must be numeric")
	}
	if _, err := strconv.ParseInt(installationID, 10, 64); err != nil {
		return fmt.Errorf("GITHUB_INSTALLATION_ID must be numeric")
	}
	return nil
}
