package auth

import (
	"context"
	"fmt"
	"os"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// GoogleGroupsConfig configures how the backend authenticates to the
// Google Admin SDK for reading Workspace group memberships.
type GoogleGroupsConfig struct {
	// Mode selects the authentication strategy.
	//   "admin-role" — SA has Groups Reader admin role in Workspace (no DWD).
	//   "dwd-keyfile" — SA key file with domain-wide delegation.
	//   "dwd-keyless" — ADC + IAM impersonation for keyless DWD.
	//   "dwd-adc"     — plain ADC with Subject (ADC must be a SA key).
	Mode string

	// SAKeyFile is the path to a SA JSON key (dwd-keyfile mode).
	SAKeyFile string
	// SAEmail is the SA email for keyless impersonation (dwd-keyless mode).
	SAEmail string
	// AdminEmail is the Workspace super-admin for DWD subject impersonation.
	// Required for dwd-* modes, must be empty for admin-role mode.
	AdminEmail string

	// Domain is the Workspace domain (e.g. "example.com").
	// Required for admin-role mode. Inferred from AllowedDomains in startup if not set.
	Domain string

	// Transitive resolves nested group memberships when true.
	Transitive bool
}

// InferGoogleGroupsMode determines the auth mode from the provided fields.
// This keeps the caller (startup.go) simple — just populate what you have.
func InferGoogleGroupsMode(saKeyFile, saEmail, adminEmail string) string {
	switch {
	case adminEmail == "":
		return "admin-role"
	case saKeyFile != "":
		return "dwd-keyfile"
	case saEmail != "":
		return "dwd-keyless"
	default:
		return "dwd-adc"
	}
}

// GroupsResolver resolves Google Workspace group memberships for a user
// using the Admin SDK Directory API.
type GroupsResolver struct {
	adminSrv   *admin.Service
	transitive bool
	domain     string // Workspace domain, required for admin-role mode
}

// NewGoogleGroupsResolver creates a resolver using the specified config.
func NewGoogleGroupsResolver(ctx context.Context, cfg GoogleGroupsConfig) (*GroupsResolver, error) {
	opts, err := googleGroupsClientOpts(ctx, cfg)
	if err != nil {
		return nil, err
	}

	srv, err := admin.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create admin service: %w", err)
	}

	return &GroupsResolver{
		adminSrv:   srv,
		transitive: cfg.Transitive,
		domain:     cfg.Domain,
	}, nil
}

// NewGroupsResolver is a convenience constructor that infers the mode from the provided fields.
// Kept for backward compatibility with existing callers and tests.
func NewGroupsResolver(ctx context.Context, saKeyFile, saEmail, adminEmail string, transitive bool) (*GroupsResolver, error) {
	return NewGoogleGroupsResolver(ctx, GoogleGroupsConfig{
		Mode:       InferGoogleGroupsMode(saKeyFile, saEmail, adminEmail),
		SAKeyFile:  saKeyFile,
		SAEmail:    saEmail,
		AdminEmail: adminEmail,
		Transitive: transitive,
	})
}

func googleGroupsClientOpts(ctx context.Context, cfg GoogleGroupsConfig) ([]option.ClientOption, error) {
	switch cfg.Mode {
	case "admin-role":
		// SA has Groups Reader admin role in Workspace. Self-impersonate to
		// obtain a token with the Admin SDK scope (the metadata server's
		// cloud-platform scope is not accepted by the Admin SDK).
		saEmail := cfg.SAEmail
		if saEmail == "" {
			// Auto-detect from metadata server on GCE/Cloud Run.
			email, err := metadata.EmailWithContext(ctx, "")
			if err != nil {
				return nil, fmt.Errorf("admin-role mode requires -google-sa-email or GCE metadata: %w", err)
			}
			saEmail = email
		}
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: saEmail,
			Scopes:          []string{admin.AdminDirectoryGroupReadonlyScope},
		})
		if err != nil {
			return nil, fmt.Errorf("create credentials for groups reader: %w", err)
		}
		return []option.ClientOption{option.WithTokenSource(ts)}, nil

	case "dwd-keyfile":
		jsonKey, err := os.ReadFile(cfg.SAKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read service account key: %w", err)
		}
		jwtConfig, err := google.JWTConfigFromJSON(jsonKey, admin.AdminDirectoryGroupReadonlyScope)
		if err != nil {
			return nil, fmt.Errorf("parse service account key: %w", err)
		}
		jwtConfig.Subject = cfg.AdminEmail
		return []option.ClientOption{option.WithHTTPClient(jwtConfig.Client(ctx))}, nil

	case "dwd-keyless":
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: cfg.SAEmail,
			Scopes:          []string{admin.AdminDirectoryGroupReadonlyScope},
			Subject:         cfg.AdminEmail,
		})
		if err != nil {
			return nil, fmt.Errorf("impersonate SA for DWD: %w", err)
		}
		return []option.ClientOption{option.WithTokenSource(ts)}, nil

	case "dwd-adc":
		creds, err := google.FindDefaultCredentialsWithParams(ctx, google.CredentialsParams{
			Scopes:  []string{admin.AdminDirectoryGroupReadonlyScope},
			Subject: cfg.AdminEmail,
		})
		if err != nil {
			return nil, fmt.Errorf("find default credentials: %w", err)
		}
		return []option.ClientOption{option.WithCredentials(creds)}, nil

	default:
		return nil, fmt.Errorf("unknown google groups mode: %q", cfg.Mode)
	}
}

// ResolveGroups returns all Google Workspace group emails that the user belongs to.
// If transitive is true, nested group memberships are recursively resolved.
func (g *GroupsResolver) ResolveGroups(ctx context.Context, email string) ([]string, error) {
	checkedGroups := make(map[string]struct{})
	return g.getGroups(email, checkedGroups)
}

// getGroups lists groups for a user/group email with pagination and optional
// transitive resolution with cycle detection.
func (g *GroupsResolver) getGroups(email string, checkedGroups map[string]struct{}) ([]string, error) {
	var userGroups []string
	pageToken := ""

	for {
		call := g.adminSrv.Groups.List().
			UserKey(email).
			PageToken(pageToken)
		// When using admin-role mode (no DWD), the domain must be set explicitly
		// because the SA has no implicit Workspace identity.
		if g.domain != "" {
			call = call.Domain(g.domain)
		}
		resp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("list groups for %s: %w", email, err)
		}

		for _, group := range resp.Groups {
			if _, exists := checkedGroups[group.Email]; exists {
				continue
			}
			checkedGroups[group.Email] = struct{}{}
			userGroups = append(userGroups, group.Email)

			if g.transitive {
				transitiveGroups, err := g.getGroups(group.Email, checkedGroups)
				if err != nil {
					return nil, fmt.Errorf("transitive groups for %s: %w", group.Email, err)
				}
				userGroups = append(userGroups, transitiveGroups...)
			}
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return userGroups, nil
}
