package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/hatemosphere/pulumi-backend/internal/audit"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// registerLogin registers browser-based login routes on a huma API.
// Uses StreamResponse so handlers can serve HTML, set cookies, and redirect.
func (s *Server) registerLogin(api huma.API) {
	slog.Info("registering login routes", "routes", []string{"/login", "/login/callback", "/cli-login", "/welcome/cli"})

	// --- Login page ---
	huma.Register(api, huma.Operation{
		OperationID: "loginPage",
		Method:      http.MethodGet,
		Path:        "/login",
		Tags:        []string{"Auth"},
	}, func(_ context.Context, _ *struct{}) (*huma.StreamResponse, error) {
		return &huma.StreamResponse{
			Body: func(ctx huma.Context) {
				csrfToken := generateCSRFToken()
				if csrfToken == "" {
					ctx.SetStatus(http.StatusInternalServerError)
					return
				}

				state := "csrf:" + csrfToken

				redirectURI := s.loginRedirectURI(ctx)
				authURL, oidcNonce := s.oidcAuth.AuthCodeURL(redirectURI, state)
				s.setOAuthStateCookieHuma(ctx, csrfToken, oidcNonce)

				ctx.SetHeader("Content-Type", "text/html; charset=utf-8")
				if err := loginPageTmpl.Execute(ctx.BodyWriter(), map[string]string{
					"AuthURL":      authURL,
					"ProviderName": s.oidcAuth.Config().ProviderName,
				}); err != nil {
					slog.Error("render login page", "error", err)
				}
			},
		}, nil
	})

	// --- Login callback ---
	huma.Register(api, huma.Operation{
		OperationID: "loginCallback",
		Method:      http.MethodGet,
		Path:        "/login/callback",
		Tags:        []string{"Auth"},
	}, func(ctx context.Context, input *LoginCallbackInput) (*huma.StreamResponse, error) {
		return &huma.StreamResponse{
			Body: func(hCtx huma.Context) {
				s.handleLoginCallbackHuma(hCtx, ctx, input)
			},
		}, nil
	})

	// --- CLI login ---
	huma.Register(api, huma.Operation{
		OperationID: "cliLogin",
		Method:      http.MethodGet,
		Path:        "/cli-login",
		Tags:        []string{"Auth"},
	}, func(_ context.Context, input *CLILoginInput) (*huma.StreamResponse, error) {
		return &huma.StreamResponse{
			Body: func(ctx huma.Context) {
				if input.SessionPort == "" || input.SessionNonce == "" {
					ctx.SetHeader("Content-Type", "text/html; charset=utf-8")
					renderErrorToWriter(ctx.BodyWriter(), "Missing cliSessionPort or cliSessionNonce parameters.")
					return
				}

				// Fix 3: Validate CLI port is a valid integer in range 1-65535.
				port, err := strconv.Atoi(input.SessionPort)
				if err != nil || port < 1 || port > 65535 {
					ctx.SetHeader("Content-Type", "text/html; charset=utf-8")
					renderErrorToWriter(ctx.BodyWriter(), "Invalid cliSessionPort value.")
					return
				}

				csrfToken := generateCSRFToken()
				if csrfToken == "" {
					ctx.SetStatus(http.StatusInternalServerError)
					return
				}

				state := fmt.Sprintf("cli:%d:%s:%s", port, input.SessionNonce, csrfToken)

				// Fix 5: Store CLI session nonce server-side keyed by CSRF token.
				s.cliSessionNonces.Set(csrfToken, input.SessionNonce)

				redirectURI := s.loginRedirectURI(ctx)
				authURL, oidcNonce := s.oidcAuth.AuthCodeURL(redirectURI, state)
				s.setOAuthStateCookieHuma(ctx, csrfToken, oidcNonce)

				ctx.SetHeader("Location", authURL)
				ctx.SetStatus(http.StatusTemporaryRedirect)
			},
		}, nil
	})

	// --- Welcome page (post-CLI-login) ---
	huma.Register(api, huma.Operation{
		OperationID: "welcomeCLI",
		Method:      http.MethodGet,
		Path:        "/welcome/cli",
		Tags:        []string{"Auth"},
	}, func(_ context.Context, _ *struct{}) (*huma.StreamResponse, error) {
		return &huma.StreamResponse{
			Body: func(ctx huma.Context) {
				ctx.SetHeader("Content-Type", "text/html; charset=utf-8")
				if err := welcomePageTmpl.Execute(ctx.BodyWriter(), nil); err != nil {
					slog.Error("render welcome page", "error", err)
				}
			},
		}, nil
	})
}

// handleLoginCallbackHuma handles the OAuth2 callback from the OIDC provider.
// Works for both browser login (state starts with "csrf:") and CLI login (state starts with "cli:").
func (s *Server) handleLoginCallbackHuma(hCtx huma.Context, goCtx context.Context, input *LoginCallbackInput) {
	hCtx.SetHeader("Content-Type", "text/html; charset=utf-8")

	if input.OAuthError != "" {
		renderErrorToWriter(hCtx.BodyWriter(), "Login failed: "+input.OAuthError)
		return
	}

	if input.State == "" {
		renderErrorToWriter(hCtx.BodyWriter(), "Missing state parameter. Please try logging in again.")
		return
	}

	// Extract CSRF token from state and verify against cookie.
	csrfToken := extractCSRFToken(input.State)
	if input.OAuthState == "" || input.OAuthState != csrfToken {
		renderErrorToWriter(hCtx.BodyWriter(), "Invalid state parameter. Please try logging in again.")
		return
	}

	// Clear the state and nonce cookies.
	clearStateCookie := &http.Cookie{Name: "oauth_state", Value: "", Path: "/", MaxAge: -1}
	hCtx.AppendHeader("Set-Cookie", clearStateCookie.String())
	clearNonceCookie := &http.Cookie{Name: "oidc_nonce", Value: "", Path: "/", MaxAge: -1}
	hCtx.AppendHeader("Set-Cookie", clearNonceCookie.String())

	if input.Code == "" {
		renderErrorToWriter(hCtx.BodyWriter(), "Missing authorization code.")
		return
	}

	// Build the redirect URI (must match what was sent to the provider).
	redirectURI := s.loginRedirectURI(hCtx)

	// Exchange the authorization code for tokens, validating the OIDC nonce.
	codeResult, err := s.oidcAuth.ExchangeCode(goCtx, input.Code, redirectURI, input.OIDCNonce)
	if err != nil {
		slog.Error("code exchange failed", "error", err)
		renderErrorToWriter(hCtx.BodyWriter(), "Failed to exchange authorization code. Please try again.")
		return
	}

	// Validate the ID token and mint a backend access token.
	result, err := s.oidcAuth.Exchange(goCtx, codeResult.IDToken)
	if err != nil {
		slog.Error("ID token exchange failed", "error", err)
		audit.Event{
			Actor:  "anonymous",
			Action: "login_attempt",
			Status: "failed",
			Reason: "id_token_exchange_failed",
			IP:     hCtx.RemoteAddr(),
			Extra:  []any{slog.String("error", err.Error())},
		}.Warn("Audit Log: Login Failed")
		renderErrorToWriter(hCtx.BodyWriter(), "Authentication failed: "+err.Error())
		return
	}

	// Persist the token in the database.
	if err := s.tokenStore.CreateToken(goCtx, &storage.Token{
		TokenHash:    result.TokenHash,
		UserName:     result.UserName,
		Description:  tokenDescription(input.State),
		RefreshToken: codeResult.RefreshToken,
		Groups:       result.Groups,
		ExpiresAt:    &result.ExpiresAt,
	}); err != nil {
		slog.Error("failed to store token", "error", err)
		renderErrorToWriter(hCtx.BodyWriter(), "Failed to create access token. Please try again.")
		return
	}

	if codeResult.RefreshToken != "" {
		slog.Info("stored refresh token for re-validation", "user", result.UserName) //nolint:gosec // structured logger
	}

	audit.Event{
		Actor:      result.UserName,
		Action:     "login_success",
		Status:     "granted",
		AuthMethod: "oidc",
		IP:         hCtx.RemoteAddr(),
	}.Info("Audit Log: Login Success")

	// CLI login flow: redirect to the CLI's local server with the token.
	if strings.HasPrefix(input.State, "cli:") {
		portStr, nonce := parseCLIState(input.State)
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			renderErrorToWriter(hCtx.BodyWriter(), "Invalid CLI session port.")
			return
		}
		// Fix 5: Validate CLI session nonce against server-side store.
		if !s.cliSessionNonces.Validate(csrfToken, nonce) {
			renderErrorToWriter(hCtx.BodyWriter(), "Invalid CLI session nonce. Please try logging in again.")
			return
		}
		cliURL := fmt.Sprintf("http://localhost:%d/?accessToken=%s&nonce=%s",
			port, url.QueryEscape(result.Token), url.QueryEscape(nonce))
		hCtx.SetHeader("Location", cliURL)
		hCtx.SetStatus(http.StatusTemporaryRedirect)
		return
	}

	// Browser login flow: show the token page.
	loginURL := s.loginBaseURL(hCtx)
	if err := callbackSuccessTmpl.Execute(hCtx.BodyWriter(), map[string]any{
		"UserName": result.UserName,
		"Token":    result.Token,
		"LoginURL": loginURL,
	}); err != nil {
		slog.Error("render callback page", "error", err)
	}
}

// --- Helpers ---

func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// setOAuthStateCookieHuma sets the OAuth state and OIDC nonce cookies.
func (s *Server) setOAuthStateCookieHuma(ctx huma.Context, csrfToken, oidcNonce string) {
	secure := isHTTPS(ctx, s.publicURL)
	stateCookie := &http.Cookie{
		Name:     "oauth_state",
		Value:    csrfToken,
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	}
	ctx.AppendHeader("Set-Cookie", stateCookie.String())
	nonceCookie := &http.Cookie{
		Name:     "oidc_nonce",
		Value:    oidcNonce,
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	}
	ctx.AppendHeader("Set-Cookie", nonceCookie.String())
}

// isHTTPS returns true if the request uses HTTPS, determined from TLS state,
// X-Forwarded-Proto header, or the configured public URL.
func isHTTPS(ctx huma.Context, publicURL string) bool {
	if ctx.TLS() != nil || ctx.Header("X-Forwarded-Proto") == "https" {
		return true
	}
	return strings.HasPrefix(publicURL, "https://")
}

// loginRedirectURI returns the OAuth2 redirect URI for the login callback.
// Uses publicURL when configured to prevent Host header poisoning.
func (s *Server) loginRedirectURI(ctx huma.Context) string {
	if s.publicURL != "" {
		return s.publicURL + "/login/callback"
	}
	slog.Warn("public-url not set, using Host header for redirect URI (set --public-url to avoid Host header attacks)")
	scheme := schemeFromCtx(ctx)
	return fmt.Sprintf("%s://%s/login/callback", scheme, ctx.Host())
}

// loginBaseURL returns the base URL for the login page link.
func (s *Server) loginBaseURL(ctx huma.Context) string {
	if s.publicURL != "" {
		return s.publicURL
	}
	scheme := schemeFromCtx(ctx)
	return fmt.Sprintf("%s://%s", scheme, ctx.Host())
}

// schemeFromCtx determines the request scheme from TLS state and headers.
func schemeFromCtx(ctx huma.Context) string {
	if ctx.TLS() != nil || ctx.Header("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}

// extractCSRFToken extracts the CSRF token from the OAuth state string.
// State formats: "csrf:<token>" or "cli:<port>:<nonce>:<token>".
func extractCSRFToken(state string) string {
	if after, ok := strings.CutPrefix(state, "csrf:"); ok {
		return after
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

func renderErrorToWriter(w io.Writer, msg string) {
	if err := errorPageTmpl.Execute(w, map[string]string{"Error": msg}); err != nil {
		slog.Error("render error page", "error", err)
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
  .sso-btn { display: inline-flex; align-items: center; gap: 12px; background: #fff; border: 1px solid #dadce0; border-radius: 8px; padding: 12px 24px; font-size: 16px; color: #3c4043; text-decoration: none; cursor: pointer; transition: background 0.2s, box-shadow 0.2s; }
  .sso-btn:hover { background: #f8f9fa; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
  .sso-btn svg { width: 20px; height: 20px; }
</style>
</head>
<body>
<div class="card">
  <h1>Pulumi Backend</h1>
  <p class="subtitle">Sign in to get your access token</p>
  <a href="{{.AuthURL}}" class="sso-btn">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
    Sign in with {{.ProviderName}}
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
