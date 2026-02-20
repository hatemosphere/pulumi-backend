package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

func (s *Server) registerTokenExchange(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "tokenExchange",
		Method:      http.MethodPost,
		Path:        "/api/auth/token-exchange",
		Tags:        []string{"Auth"},
	}, func(ctx context.Context, input *TokenExchangeInput) (*TokenExchangeOutput, error) {
		if input.Body.IDToken == "" {
			return nil, huma.NewError(http.StatusBadRequest, "idToken is required")
		}

		result, err := s.oidcAuth.Exchange(ctx, input.Body.IDToken)
		if err != nil {
			return nil, huma.NewError(http.StatusUnauthorized, err.Error())
		}

		// Persist the token in the database.
		if err := s.tokenStore.CreateToken(ctx, &storage.Token{
			TokenHash:   result.TokenHash,
			UserName:    result.UserName,
			Description: "oidc-token-exchange",
			Groups:      result.Groups,
			ExpiresAt:   &result.ExpiresAt,
		}); err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, "failed to store token")
		}

		out := &TokenExchangeOutput{}
		out.Body.Token = result.Token
		out.Body.UserName = result.UserName
		out.Body.ExpiresAt = result.ExpiresAt.Unix()
		return out, nil
	})
}
