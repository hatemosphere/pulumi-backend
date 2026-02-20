package auth

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
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
// If saKeyFile is provided, it is read and used for domain-wide delegation via
// JWT credentials with Subject set to adminEmail. If saKeyFile is empty,
// Application Default Credentials (ADC) are used instead — this supports
// Workload Identity in GKE, GOOGLE_APPLICATION_CREDENTIALS env var, and
// gcloud auth application-default login. The underlying service account must
// have domain-wide delegation with the AdminDirectoryGroupReadonlyScope scope.
func NewGroupsResolver(ctx context.Context, saKeyFile, adminEmail string, transitive bool) (*GroupsResolver, error) {
	var opts []option.ClientOption

	if saKeyFile != "" {
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
	} else {
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
