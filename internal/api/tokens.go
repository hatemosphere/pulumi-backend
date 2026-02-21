package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

func (s *Server) registerUserTokens(api huma.API) {
	// --- List personal tokens ---
	huma.Register(api, huma.Operation{
		OperationID: "listPersonalTokens",
		Method:      http.MethodGet,
		Path:        "/api/user/tokens",
		Tags:        []string{"User"},
	}, func(ctx context.Context, input *struct{}) (*ListPersonalTokensOutput, error) {
		identity, err := requireIdentity(ctx)
		if err != nil {
			return nil, err
		}

		tokens, err := s.tokenStore.ListTokensByUser(ctx, identity.UserName)
		if err != nil {
			return nil, internalError(err)
		}

		out := &ListPersonalTokensOutput{}
		out.Body.Tokens = make([]AccessTokenInfo, 0, len(tokens))
		for _, t := range tokens {
			out.Body.Tokens = append(out.Body.Tokens, tokenToAccessTokenInfo(t))
		}
		return out, nil
	})

	// --- Create personal token ---
	huma.Register(api, huma.Operation{
		OperationID: "createPersonalToken",
		Method:      http.MethodPost,
		Path:        "/api/user/tokens",
		Tags:        []string{"User"},
		Errors:      []int{400},
	}, func(ctx context.Context, input *CreatePersonalTokenInput) (*CreatePersonalTokenOutput, error) {
		identity, err := requireIdentity(ctx)
		if err != nil {
			return nil, err
		}

		if input.Body.Description == "" {
			return nil, huma.NewError(http.StatusBadRequest, "description is required")
		}

		rawToken, err := auth.GenerateToken()
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, "failed to generate token")
		}
		tokenHash := auth.HashToken(rawToken)

		tok := &storage.Token{
			TokenHash:   tokenHash,
			UserName:    identity.UserName,
			Description: input.Body.Description,
			CreatedAt:   time.Now(),
		}
		if input.Body.Expires > 0 {
			exp := time.Unix(input.Body.Expires, 0)
			tok.ExpiresAt = &exp
		}

		if err := s.tokenStore.CreateToken(ctx, tok); err != nil {
			return nil, internalError(err)
		}

		out := &CreatePersonalTokenOutput{}
		out.Body.ID = tokenHash
		out.Body.TokenValue = rawToken
		return out, nil
	})

	// --- Delete personal token ---
	huma.Register(api, huma.Operation{
		OperationID:   "deletePersonalToken",
		Method:        http.MethodDelete,
		Path:          "/api/user/tokens/{tokenId}",
		Tags:          []string{"User"},
		DefaultStatus: 204,
		Errors:        []int{404},
	}, func(ctx context.Context, input *DeletePersonalTokenInput) (*struct{}, error) {
		identity, err := requireIdentity(ctx)
		if err != nil {
			return nil, err
		}

		// Look up the token to verify ownership.
		tok, err := s.tokenStore.GetToken(ctx, input.TokenID)
		if err != nil {
			return nil, internalError(err)
		}
		if tok == nil || tok.UserName != identity.UserName {
			return nil, huma.NewError(http.StatusNotFound, "token not found")
		}

		if err := s.tokenStore.DeleteToken(ctx, input.TokenID); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})
}

// tokenToAccessTokenInfo converts a storage token to the upstream-compatible API type.
func tokenToAccessTokenInfo(t storage.Token) AccessTokenInfo {
	info := AccessTokenInfo{
		ID:          t.TokenHash,
		Description: t.Description,
		Created:     t.CreatedAt.UTC().Format(time.RFC3339),
	}
	if t.LastUsedAt != nil {
		info.LastUsed = t.LastUsedAt.Unix()
	}
	if t.ExpiresAt != nil {
		info.Expires = t.ExpiresAt.Unix()
	}
	return info
}
