package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

func (s *Server) registerUser(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "getUser",
		Method:      http.MethodGet,
		Path:        "/api/user",
		Tags:        []string{"User"},
	}, func(ctx context.Context, input *struct{}) (*GetUserOutput, error) {
		identity := auth.IdentityFromContext(ctx)
		userName := s.defaultUser
		isAdmin := true
		if identity != nil {
			userName = identity.UserName
			isAdmin = identity.IsAdmin
		}

		out := &GetUserOutput{}
		out.Body.GitHubLogin = userName
		out.Body.Name = userName
		out.Body.AvatarURL = ""
		out.Body.Organizations = []any{
			map[string]any{
				"githubLogin": s.defaultOrg,
				"name":        s.defaultOrg,
				"avatarUrl":   "",
			},
		}
		out.Body.Identities = []string{}
		out.Body.SiteAdmin = isAdmin
		out.Body.TokenInfo = &TokenInfo{Name: "default"}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "listUserStacks",
		Method:      http.MethodGet,
		Path:        "/api/user/stacks",
		Tags:        []string{"User"},
		Errors:      []int{400},
	}, func(ctx context.Context, input *ListUserStacksInput) (*ListUserStacksOutput, error) {
		stacks, nextToken, err := s.engine.ListStacks(ctx, input.Organization, input.Project, input.ContinuationToken)
		if err != nil {
			return nil, internalError(err)
		}

		out := &ListUserStacksOutput{}
		out.Body.Stacks = stacksToSummaries(stacks, true)
		if nextToken != "" {
			out.Body.ContinuationToken = ptrString(nextToken)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "getDefaultOrg",
		Method:      http.MethodGet,
		Path:        "/api/user/organizations/default",
		Tags:        []string{"User"},
		Errors:      []int{400},
	}, func(ctx context.Context, input *struct{}) (*GetDefaultOrgOutput, error) {
		out := &GetDefaultOrgOutput{}
		out.Body.GitHubLogin = s.defaultOrg
		out.Body.Messages = []Message{}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "listOrgStacks",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}",
		Tags:        []string{"Stacks"},
	}, func(ctx context.Context, input *ListOrgStacksInput) (*ListOrgStacksOutput, error) {
		stacks, nextToken, err := s.engine.ListStacks(ctx, input.OrgName, "", input.ContinuationToken)
		if err != nil {
			return nil, internalError(err)
		}

		out := &ListOrgStacksOutput{}
		out.Body.Stacks = stacksToSummaries(stacks, false)
		if nextToken != "" {
			out.Body.ContinuationToken = ptrString(nextToken)
		}
		return out, nil
	})
}

// stacksToSummaries converts storage stacks to API StackSummary values.
// When includeTags is true, per-stack tags are included in the output.
func stacksToSummaries(stacks []storage.Stack, includeTags bool) []StackSummary {
	result := make([]StackSummary, 0, len(stacks))
	for _, st := range stacks {
		s := StackSummary{
			OrgName:       st.OrgName,
			ProjectName:   st.ProjectName,
			StackName:     st.StackName,
			LastUpdate:    st.UpdatedAt.Unix(),
			ResourceCount: st.ResourceCount,
		}
		if includeTags {
			s.Tags = st.Tags
		}
		result = append(result, s)
	}
	return result
}
