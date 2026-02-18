package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

func (s *Server) registerUser(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "getUser",
		Method:      http.MethodGet,
		Path:        "/api/user",
		Tags:        []string{"User"},
	}, func(ctx context.Context, input *struct{}) (*GetUserOutput, error) {
		out := &GetUserOutput{}
		out.Body.GitHubLogin = s.defaultUser
		out.Body.Name = s.defaultUser
		out.Body.AvatarURL = ""
		out.Body.Organizations = []any{
			map[string]any{
				"githubLogin": s.defaultOrg,
				"name":        s.defaultOrg,
				"avatarUrl":   "",
			},
		}
		out.Body.Identities = []string{}
		out.Body.SiteAdmin = true
		out.Body.TokenInfo = &TokenInfo{Name: "default"}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "listUserStacks",
		Method:      http.MethodGet,
		Path:        "/api/user/stacks",
		Tags:        []string{"User"},
	}, func(ctx context.Context, input *ListUserStacksInput) (*ListUserStacksOutput, error) {
		stacks, nextToken, err := s.engine.ListStacks(ctx, input.Organization, input.Project, input.ContinuationToken)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}

		result := make([]StackSummary, 0, len(stacks))
		for _, st := range stacks {
			result = append(result, StackSummary{
				OrgName:       st.OrgName,
				ProjectName:   st.ProjectName,
				StackName:     st.StackName,
				LastUpdate:    st.UpdatedAt.Unix(),
				ResourceCount: st.ResourceCount,
				Tags:          st.Tags,
			})
		}

		out := &ListUserStacksOutput{}
		out.Body.Stacks = result
		if nextToken != "" {
			out.Body.ContinuationToken = &nextToken
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "getDefaultOrg",
		Method:      http.MethodGet,
		Path:        "/api/user/organizations/default",
		Tags:        []string{"User"},
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
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}

		result := make([]StackSummary, 0, len(stacks))
		for _, st := range stacks {
			result = append(result, StackSummary{
				OrgName:       st.OrgName,
				ProjectName:   st.ProjectName,
				StackName:     st.StackName,
				LastUpdate:    st.UpdatedAt.Unix(),
				ResourceCount: st.ResourceCount,
			})
		}

		out := &ListOrgStacksOutput{}
		out.Body.Stacks = result
		if nextToken != "" {
			out.Body.ContinuationToken = &nextToken
		}
		return out, nil
	})
}
