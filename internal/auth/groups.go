package auth

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// GroupsResolver resolves Google Workspace group memberships for a user
// using the Admin SDK Directory API. Follows the Dex Google connector pattern.
type GroupsResolver struct {
	adminSrv   *admin.Service
	transitive bool // resolve nested group memberships
}

// NewGroupsResolver creates a resolver that queries the Admin SDK for group membership.
//
// Credentials are resolved in order:
//  1. saKeyFile set: read the JSON key and use JWT credentials with Subject for DWD.
//  2. saEmail set (no key): use ADC + IAM impersonate API with Subject for keyless DWD.
//     Works with Workload Identity, gcloud ADC, or GOOGLE_APPLICATION_CREDENTIALS.
//  3. Neither: use plain ADC with Subject (works only when ADC is a SA key).
func NewGroupsResolver(ctx context.Context, saKeyFile, saEmail, adminEmail string, transitive bool) (*GroupsResolver, error) {
	var opts []option.ClientOption

	switch {
	case saKeyFile != "":
		// Explicit SA key file — JWT credentials with domain-wide delegation.
		jsonKey, err := os.ReadFile(saKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read service account key: %w", err)
		}
		jwtConfig, err := google.JWTConfigFromJSON(jsonKey, admin.AdminDirectoryGroupReadonlyScope)
		if err != nil {
			return nil, fmt.Errorf("parse service account key: %w", err)
		}
		jwtConfig.Subject = adminEmail
		opts = append(opts, option.WithHTTPClient(jwtConfig.Client(ctx)))

	case saEmail != "":
		// Keyless: use ADC to impersonate the SA with DWD via IAM signJwt.
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: saEmail,
			Scopes:          []string{admin.AdminDirectoryGroupReadonlyScope},
			Subject:         adminEmail,
		})
		if err != nil {
			return nil, fmt.Errorf("impersonate SA for DWD: %w", err)
		}
		opts = append(opts, option.WithTokenSource(ts))

	default:
		// Plain ADC — works when ADC is a SA key with DWD configured.
		creds, err := google.FindDefaultCredentialsWithParams(ctx, google.CredentialsParams{
			Scopes:  []string{admin.AdminDirectoryGroupReadonlyScope},
			Subject: adminEmail,
		})
		if err != nil {
			return nil, fmt.Errorf("find default credentials: %w", err)
		}
		opts = append(opts, option.WithCredentials(creds))
	}

	srv, err := admin.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create admin service: %w", err)
	}

	return &GroupsResolver{
		adminSrv:   srv,
		transitive: transitive,
	}, nil
}

// ResolveGroups returns all Google Workspace group emails that the user belongs to.
// If transitive is true, nested group memberships are recursively resolved.
func (g *GroupsResolver) ResolveGroups(ctx context.Context, email string) ([]string, error) {
	checkedGroups := make(map[string]struct{})
	return g.getGroups(email, checkedGroups)
}

// getGroups lists groups for a user/group email, following the Dex pattern of
// pagination + optional transitive resolution with cycle detection.
func (g *GroupsResolver) getGroups(email string, checkedGroups map[string]struct{}) ([]string, error) {
	var userGroups []string
	pageToken := ""

	for {
		resp, err := g.adminSrv.Groups.List().
			UserKey(email).
			PageToken(pageToken).
			Do()
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
