package api

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

func (s *Server) registerSecrets(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "encryptValue",
		Method:      http.MethodPost,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/encrypt",
		Tags:        []string{"Secrets"},
	}, func(ctx context.Context, input *EncryptValueInput) (*EncryptValueOutput, error) {
		ciphertext, err := s.engine.EncryptValue(ctx, input.OrgName, input.ProjectName, input.StackName, input.Body.Plaintext)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		out := &EncryptValueOutput{}
		out.Body.Ciphertext = ciphertext
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "decryptValue",
		Method:      http.MethodPost,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/decrypt",
		Tags:        []string{"Secrets"},
	}, func(ctx context.Context, input *DecryptValueInput) (*DecryptValueOutput, error) {
		plaintext, err := s.engine.DecryptValue(ctx, input.OrgName, input.ProjectName, input.StackName, input.Body.Ciphertext)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		out := &DecryptValueOutput{}
		out.Body.Plaintext = plaintext
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "batchEncrypt",
		Method:      http.MethodPost,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/batch-encrypt",
		Tags:        []string{"Secrets"},
	}, func(ctx context.Context, input *BatchEncryptInput) (*BatchEncryptOutput, error) {
		ciphertexts := make([][]byte, len(input.Body.Plaintexts))
		for i, pt := range input.Body.Plaintexts {
			ct, err := s.engine.EncryptValue(ctx, input.OrgName, input.ProjectName, input.StackName, pt)
			if err != nil {
				return nil, huma.NewError(http.StatusInternalServerError, err.Error())
			}
			ciphertexts[i] = ct
		}
		out := &BatchEncryptOutput{}
		out.Body.Ciphertexts = ciphertexts
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "batchDecrypt",
		Method:      http.MethodPost,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/batch-decrypt",
		Tags:        []string{"Secrets"},
	}, func(ctx context.Context, input *BatchDecryptInput) (*BatchDecryptOutput, error) {
		plaintexts := make(map[string][]byte, len(input.Body.Ciphertexts))
		for _, ct := range input.Body.Ciphertexts {
			pt, err := s.engine.DecryptValue(ctx, input.OrgName, input.ProjectName, input.StackName, ct)
			if err != nil {
				return nil, huma.NewError(http.StatusInternalServerError, err.Error())
			}
			key := base64.StdEncoding.EncodeToString(ct)
			plaintexts[key] = pt
		}
		out := &BatchDecryptOutput{}
		out.Body.Plaintexts = plaintexts
		return out, nil
	})
}
