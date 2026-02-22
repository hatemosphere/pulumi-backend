package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/hatemosphere/pulumi-backend/internal/auth"
)

func (s *Server) registerOrg(api huma.API) {
	// --- List teams (read-only, from RBAC config) ---
	huma.Register(api, huma.Operation{
		OperationID: "listTeams",
		Method:      http.MethodGet,
		Path:        "/api/orgs/{orgName}/teams",
		Tags:        []string{"Teams"},
	}, func(ctx context.Context, input *OrgNameInput) (*ListTeamsOutput, error) {
		teams := s.buildTeams(ctx)
		out := &ListTeamsOutput{}
		out.Body.Teams = teams
		return out, nil
	})

	// --- Get team (read-only) ---
	huma.Register(api, huma.Operation{
		OperationID: "getTeam",
		Method:      http.MethodGet,
		Path:        "/api/orgs/{orgName}/teams/{teamName}",
		Tags:        []string{"Teams"},
		Errors:      []int{404},
	}, func(ctx context.Context, input *GetTeamInput) (*GetTeamOutput, error) {
		teams := s.buildTeams(ctx)
		for _, t := range teams {
			if t.Name == input.TeamName {
				out := &GetTeamOutput{}
				out.Body = t
				return out, nil
			}
		}
		return nil, huma.NewError(http.StatusNotFound, "team not found")
	})

	// --- List roles (read-only, from RBAC config) ---
	huma.Register(api, huma.Operation{
		OperationID: "listRoles",
		Method:      http.MethodGet,
		Path:        "/api/orgs/{orgName}/roles",
		Tags:        []string{"Roles"},
		Errors:      []int{400},
	}, func(ctx context.Context, input *ListRolesInput) (*ListRolesOutput, error) {
		out := &ListRolesOutput{}
		out.Body.Roles = s.buildRoles()
		return out, nil
	})
}

// buildTeams constructs team info from the RBAC config.
// Each group in GroupRoles becomes a team. Stack permissions come from StackPolicies.
func (s *Server) buildTeams(ctx context.Context) []TeamInfo {
	if s.rbac == nil {
		return []TeamInfo{}
	}
	cfg := s.rbac.Config()
	if cfg == nil {
		return []TeamInfo{}
	}

	identity := auth.IdentityFromContext(ctx)

	// Collect unique groups.
	groupSet := make(map[string]bool)
	for _, gr := range cfg.GroupRoles {
		groupSet[gr.Group] = true
	}
	for _, sp := range cfg.StackPolicies {
		groupSet[sp.Group] = true
	}

	// Build set of groups the calling user belongs to.
	isAdmin := identity != nil && identity.IsAdmin
	if !isAdmin && s.rbac != nil && identity != nil {
		// Also check if user has RBAC admin permission.
		isAdmin = s.rbac.Resolve(identity, "", "", "") >= auth.PermissionAdmin
	}
	userGroups := make(map[string]struct{})
	if identity != nil {
		for _, g := range identity.Groups {
			userGroups[g] = struct{}{}
		}
	}

	teams := make([]TeamInfo, 0, len(groupSet))
	for group := range groupSet {
		// Non-admin users only see teams they belong to.
		if !isAdmin {
			if _, ok := userGroups[group]; !ok {
				continue
			}
		}

		team := TeamInfo{
			Kind:        "pulumi",
			Name:        group,
			DisplayName: group,
			Members:     []TeamMemberInfo{},
			Stacks:      []TeamStackPerm{},
		}

		// If the requesting user is in this group, show them as a member.
		if identity != nil {
			if _, ok := userGroups[group]; ok {
				team.Members = append(team.Members, TeamMemberInfo{
					Name:        identity.UserName,
					GithubLogin: identity.UserName,
					Role:        "member",
				})
			}
		}

		// Add stack permissions from StackPolicies.
		for _, sp := range cfg.StackPolicies {
			if sp.Group == group {
				team.Stacks = append(team.Stacks, TeamStackPerm{
					ProjectName: sp.StackPattern,
					StackName:   sp.StackPattern,
					Permission:  permissionToInt(sp.Permission),
				})
			}
		}

		teams = append(teams, team)
	}

	return teams
}

// buildRoles returns deduplicated roles from the RBAC config.
func (s *Server) buildRoles() []RoleInfo {
	if s.rbac == nil {
		return []RoleInfo{}
	}
	cfg := s.rbac.Config()
	if cfg == nil {
		return []RoleInfo{}
	}

	seen := make(map[string]bool)
	roles := []RoleInfo{}

	// Default permission as a role.
	if cfg.DefaultPermission != "" && !seen[cfg.DefaultPermission] {
		seen[cfg.DefaultPermission] = true
		roles = append(roles, RoleInfo{
			Name:       cfg.DefaultPermission + " (default)",
			Permission: cfg.DefaultPermission,
		})
	}

	// Each unique permission from GroupRoles.
	for _, gr := range cfg.GroupRoles {
		if !seen[gr.Permission] {
			seen[gr.Permission] = true
			roles = append(roles, RoleInfo{
				Name:       gr.Permission,
				Permission: gr.Permission,
			})
		}
	}

	// Each unique permission from StackPolicies.
	for _, sp := range cfg.StackPolicies {
		if !seen[sp.Permission] {
			seen[sp.Permission] = true
			roles = append(roles, RoleInfo{
				Name:       sp.Permission,
				Permission: sp.Permission,
			})
		}
	}

	return roles
}

// permissionToInt converts a permission string to the upstream integer code.
// 101=read, 102=write, 103=admin.
func permissionToInt(perm string) int {
	switch perm {
	case "read":
		return 101
	case "write":
		return 102
	case "admin":
		return 103
	default:
		return 0
	}
}
