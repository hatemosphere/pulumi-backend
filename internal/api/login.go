package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// registerLoginPage registers browser-based login routes on the raw mux.
// These serve HTML, not JSON, so they're registered directly instead of via huma.
func (s *Server) registerLoginPage(mux *http.ServeMux) {
	slog.Info("registering login routes", "routes", []string{"/login", "/login/callback", "/cli-login", "/welcome/cli"})
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("GET /login/callback", s.handleLoginCallback)
	// CLI browser login: Pulumi CLI opens this URL with cliSessionPort + cliSessionNonce.
	// After Google OAuth, the backend redirects back to the CLI's local HTTP server.
	mux.HandleFunc("GET /cli-login", s.handleCLILogin)
	// Welcome page shown after CLI login completes.
	mux.HandleFunc("GET /welcome/cli", s.handleWelcome)
}

// handleLoginPage serves the "Sign in with Google" page for manual browser login.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	csrfToken := generateCSRFToken()
	if csrfToken == "" {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// State format: "csrf:<token>" for browser login.
	state := "csrf:" + csrfToken
	setOAuthStateCookie(w, csrfToken)

	scheme := requestScheme(r)
	redirectURI := fmt.Sprintf("%s://%s/login/callback", scheme, r.Host)
	authURL := s.googleAuthURL(redirectURI, state)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginPageTmpl.Execute(w, map[string]string{"AuthURL": authURL}); err != nil {
		slog.Error("render login page", "error", err)
	}
}

// handleCLILogin handles the Pulumi CLI's browser-based login flow.
// The CLI opens this URL with cliSessionPort, cliSessionNonce, and cliSessionDescription.
// We redirect to Google OAuth; on callback, instead of showing a page, we redirect
// to the CLI's local HTTP server at http://localhost:PORT/?accessToken=TOKEN&nonce=NONCE.
func (s *Server) handleCLILogin(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("cliSessionPort")
	nonce := r.URL.Query().Get("cliSessionNonce")
	if port == "" || nonce == "" {
		renderError(w, "Missing cliSessionPort or cliSessionNonce parameters.")
		return
	}

	csrfToken := generateCSRFToken()
	if csrfToken == "" {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// State format: "cli:<port>:<nonce>:<csrf>" for CLI login.
	state := fmt.Sprintf("cli:%s:%s:%s", port, nonce, csrfToken)
	setOAuthStateCookie(w, csrfToken)

	scheme := requestScheme(r)
	redirectURI := fmt.Sprintf("%s://%s/login/callback", scheme, r.Host)
	authURL := s.googleAuthURL(redirectURI, state)

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// handleLoginCallback handles the OAuth2 callback from Google.
// Works for both browser login (state starts with "csrf:") and CLI login (state starts with "cli:").
func (s *Server) handleLoginCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Check for OAuth error.
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		renderError(w, "Google login failed: "+errParam)
		return
	}

	state := r.URL.Query().Get("state")
	if state == "" {
		renderError(w, "Missing state parameter. Please try logging in again.")
		return
	}

	// Extract CSRF token from state and verify against cookie.
	csrfToken := extractCSRFToken(state)
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value == "" || stateCookie.Value != csrfToken {
		renderError(w, "Invalid state parameter. Please try logging in again.")
		return
	}

	// Clear the state cookie.
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	code := r.URL.Query().Get("code")
	if code == "" {
		renderError(w, "Missing authorization code.")
		return
	}

	// Build the redirect URI (must match what was sent to Google).
	scheme := requestScheme(r)
	redirectURI := fmt.Sprintf("%s://%s/login/callback", scheme, r.Host)

	// Exchange the authorization code for tokens.
	codeResult, err := s.exchangeCodeForIDToken(code, redirectURI)
	if err != nil {
		slog.Error("code exchange failed", "error", err)
		renderError(w, "Failed to exchange authorization code. Please try again.")
		return
	}

	// Validate the ID token and mint a backend access token.
	result, err := s.googleAuth.Exchange(r.Context(), codeResult.IDToken)
	if err != nil {
		slog.Error("ID token exchange failed", "error", err)

		// Audit Log: Login Failed
		slog.Warn("Audit Log: Login Failed", //nolint:gosec // structured logger safely escapes taint
			slog.Group("audit",
				slog.String("actor", "anonymous"),
				slog.String("action", "login_attempt"),
				slog.String("status", "failed"),
				slog.String("reason", "id_token_exchange_failed"),
				slog.String("error", err.Error()),
				slog.String("ip_address", r.RemoteAddr),
			),
		)

		renderError(w, "Authentication failed: "+err.Error())
		return
	}

	// Persist the token in the database, including the refresh token for
	// later re-validation against Google (Dex pattern: deactivated users
	// will be detected when the refresh token is rejected).
	if err := s.tokenStore.CreateToken(r.Context(), &storage.Token{
		TokenHash:    result.TokenHash,
		UserName:     result.UserName,
		Description:  tokenDescription(state),
		RefreshToken: codeResult.RefreshToken,
		ExpiresAt:    &result.ExpiresAt,
	}); err != nil {
		slog.Error("failed to store token", "error", err)
		renderError(w, "Failed to create access token. Please try again.")
		return
	}

	if codeResult.RefreshToken != "" {
		slog.Info("stored refresh token for re-validation", "user", result.UserName) //nolint:gosec // structured logger
	}

	// Audit Log: Login Success
	slog.Info("Audit Log: Login Success", //nolint:gosec // structured logger safely escapes taint
		slog.Group("audit",
			slog.String("actor", result.UserName),
			slog.String("action", "login_success"),
			slog.String("status", "granted"),
			slog.String("auth_method", "google-oauth"),
			slog.String("ip_address", r.RemoteAddr),
		),
	)

	// CLI login flow: redirect to the CLI's local server with the token.
	if strings.HasPrefix(state, "cli:") {
		port, nonce := parseCLIState(state)
		if port != "" && nonce != "" {
			cliURL := fmt.Sprintf("http://localhost:%s/?accessToken=%s&nonce=%s",
				port, url.QueryEscape(result.Token), url.QueryEscape(nonce))
			http.Redirect(w, r, cliURL, http.StatusTemporaryRedirect)
			return
		}
	}

	// Browser login flow: show the token page.
	loginURL := fmt.Sprintf("%s://%s", scheme, r.Host)
	if err := callbackSuccessTmpl.Execute(w, map[string]any{
		"UserName": result.UserName,
		"Token":    result.Token,
		"LoginURL": loginURL,
	}); err != nil {
		slog.Error("render callback page", "error", err)
	}
}

// handleWelcome serves a simple "login complete" page after CLI login.
func (s *Server) handleWelcome(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := welcomePageTmpl.Execute(w, nil); err != nil {
		slog.Error("render welcome page", "error", err)
	}
}

// --- Helpers ---

func generateCSRFToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func setOAuthStateCookie(w http.ResponseWriter, csrfToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    csrfToken,
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}

// googleAuthURL builds the Google OAuth2 authorization URL.
func (s *Server) googleAuthURL(redirectURI, state string) string {
	return fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s&access_type=offline&prompt=select_account",
		url.QueryEscape(s.googleAuth.Config().ClientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape("openid email profile"),
		url.QueryEscape(state),
	)
}

// extractCSRFToken extracts the CSRF token from the OAuth state string.
// State formats: "csrf:<token>" or "cli:<port>:<nonce>:<token>".
func extractCSRFToken(state string) string {
	if strings.HasPrefix(state, "csrf:") {
		return strings.TrimPrefix(state, "csrf:")
	}
	if strings.HasPrefix(state, "cli:") {
		parts := strings.SplitN(state, ":", 4)
		if len(parts) == 4 {
			return parts[3]
		}
	}
	return ""
}

// parseCLIState extracts port and nonce from a CLI login state string.
// State format: "cli:<port>:<nonce>:<csrf>".
func parseCLIState(state string) (port, nonce string) {
	parts := strings.SplitN(state, ":", 4)
	if len(parts) >= 3 {
		return parts[1], parts[2]
	}
	return "", ""
}

// tokenDescription returns a human-readable description for the stored token.
func tokenDescription(state string) string {
	if strings.HasPrefix(state, "cli:") {
		return "cli-login"
	}
	return "browser-login"
}

// codeExchangeResult contains the tokens returned from Google's authorization code exchange.
type codeExchangeResult struct {
	IDToken      string
	RefreshToken string //nolint:gosec // field name, not a credential
}

// exchangeCodeForIDToken exchanges an OAuth2 authorization code for tokens
// via Google's token endpoint. Returns the ID token and (if available) the
// refresh token for later re-validation.
func (s *Server) exchangeCodeForIDToken(code, redirectURI string) (*codeExchangeResult, error) {
	data := url.Values{
		"code":          {code},
		"client_id":     {s.googleAuth.Config().ClientID},
		"client_secret": {s.googleClientSecret},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}

	resp, err := http.Post( //nolint:gosec // URL is constant
		"https://oauth2.googleapis.com/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		IDToken      string `json:"id_token"`      //nolint:tagliatelle // Google API naming
		RefreshToken string `json:"refresh_token"` //nolint:tagliatelle,gosec // Google API naming
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	if tokenResp.IDToken == "" {
		return nil, errors.New("no id_token in response")
	}

	return &codeExchangeResult{
		IDToken:      tokenResp.IDToken,
		RefreshToken: tokenResp.RefreshToken,
	}, nil
}

func renderError(w http.ResponseWriter, msg string) {
	if err := errorPageTmpl.Execute(w, map[string]string{"Error": msg}); err != nil {
		slog.Error("render error page", "error", err)
		http.Error(w, msg, http.StatusInternalServerError)
	}
}

// --- HTML Templates ---

var loginPageTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pulumi Backend — Sign In</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); padding: 48px 40px; max-width: 420px; width: 100%; text-align: center; }
  h1 { font-size: 24px; margin-bottom: 8px; color: #1a1a2e; }
  .subtitle { color: #666; margin-bottom: 32px; font-size: 14px; }
  .google-btn { display: inline-flex; align-items: center; gap: 12px; background: #fff; border: 1px solid #dadce0; border-radius: 8px; padding: 12px 24px; font-size: 16px; color: #3c4043; text-decoration: none; cursor: pointer; transition: background 0.2s, box-shadow 0.2s; }
  .google-btn:hover { background: #f8f9fa; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
  .google-btn svg { width: 20px; height: 20px; }
</style>
</head>
<body>
<div class="card">
  <h1>Pulumi Backend</h1>
  <p class="subtitle">Sign in to get your access token</p>
  <a href="{{.AuthURL}}" class="google-btn">
    <svg viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
    Sign in with Google
  </a>
</div>
</body>
</html>`))

var callbackSuccessTmpl = template.Must(template.New("callback").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pulumi Backend — Signed In</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); padding: 48px 40px; max-width: 560px; width: 100%; }
  h1 { font-size: 24px; margin-bottom: 4px; color: #1a1a2e; }
  .user { color: #666; margin-bottom: 24px; font-size: 14px; }
  .section { margin-bottom: 20px; }
  .label { font-size: 12px; font-weight: 600; color: #888; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
  .token-box { display: flex; gap: 8px; align-items: center; }
  .token-input { flex: 1; font-family: "SF Mono", Monaco, Consolas, monospace; font-size: 13px; padding: 10px 12px; border: 1px solid #dadce0; border-radius: 6px; background: #f8f9fa; color: #333; outline: none; }
  .copy-btn { padding: 10px 16px; background: #4285f4; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; white-space: nowrap; }
  .copy-btn:hover { background: #3367d6; }
  .commands { background: #1a1a2e; color: #e0e0e0; border-radius: 8px; padding: 16px 20px; font-family: "SF Mono", Monaco, Consolas, monospace; font-size: 13px; line-height: 1.8; overflow-x: auto; }
  .commands .comment { color: #666; }
</style>
</head>
<body>
<div class="card">
  <h1>Signed in successfully</h1>
  <p class="user">{{.UserName}}</p>
  <div class="section">
    <div class="label">Access Token</div>
    <div class="token-box">
      <input type="text" class="token-input" id="token" value="{{.Token}}" readonly>
      <button class="copy-btn" onclick="copyToken()">Copy</button>
    </div>
  </div>
  <div class="section">
    <div class="label">Usage</div>
    <div class="commands"><span class="comment"># Set the token</span>
export PULUMI_ACCESS_TOKEN={{.Token}}

<span class="comment"># Login to the backend</span>
pulumi login {{.LoginURL}}</div>
  </div>
</div>
<script>
function copyToken() {
  var t = document.getElementById('token');
  t.select();
  navigator.clipboard.writeText(t.value).then(function() {
    var btn = document.querySelector('.copy-btn');
    btn.textContent = 'Copied!';
    setTimeout(function() { btn.textContent = 'Copy'; }, 2000);
  });
}
</script>
</body>
</html>`))

var welcomePageTmpl = template.Must(template.New("welcome").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pulumi Backend — Welcome</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); padding: 48px 40px; max-width: 420px; width: 100%; text-align: center; }
  h1 { font-size: 24px; margin-bottom: 12px; color: #1a1a2e; }
  .msg { color: #666; font-size: 14px; }
</style>
</head>
<body>
<div class="card">
  <h1>Login Complete</h1>
  <p class="msg">You can close this tab and return to your terminal.</p>
</div>
</body>
</html>`))

var errorPageTmpl = template.Must(template.New("error").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pulumi Backend — Error</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); padding: 48px 40px; max-width: 420px; width: 100%; text-align: center; }
  h1 { font-size: 24px; margin-bottom: 12px; color: #d93025; }
  .msg { color: #666; margin-bottom: 24px; font-size: 14px; }
  .retry-btn { display: inline-block; padding: 10px 24px; background: #4285f4; color: #fff; border-radius: 6px; text-decoration: none; font-size: 14px; }
  .retry-btn:hover { background: #3367d6; }
</style>
</head>
<body>
<div class="card">
  <h1>Login Failed</h1>
  <p class="msg">{{.Error}}</p>
  <a href="/login" class="retry-btn">Try Again</a>
</div>
</body>
</html>`))
