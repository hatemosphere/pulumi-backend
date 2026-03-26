package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStackHandlers_ProjectExists404(t *testing.T) {
	api := newTestAPI(t)
	rec := api.do(http.MethodHead, "/api/stacks/organization/missing-project", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestStackHandlers_UserAndDefaultOrg(t *testing.T) {
	api := newTestAPI(t)

	t.Run("user", func(t *testing.T) {
		rec := api.do(http.MethodGet, "/api/user", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var body map[string]any
		api.jsonBody(rec, &body)
		assert.Equal(t, "test-user", body["githubLogin"])
		assert.NotNil(t, body["tokenInfo"])
		assert.NotNil(t, body["organizations"])
	})

	t.Run("default org", func(t *testing.T) {
		rec := api.do(http.MethodGet, "/api/user/organizations/default", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var body map[string]any
		api.jsonBody(rec, &body)
		assert.Equal(t, "organization", body["GitHubLogin"])
		assert.Nil(t, body["githubLogin"])
	})
}

func TestStackHandlers_CreateStackMissingName(t *testing.T) {
	api := newTestAPI(t)
	rec := api.do(http.MethodPost, "/api/stacks/organization/project", map[string]string{"stackName": ""})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "stackName is required")
}

func TestStackHandlers_CreateAndGetStack(t *testing.T) {
	api := newTestAPI(t)

	rec := api.do(http.MethodPost, "/api/stacks/organization/project", map[string]string{"stackName": "dev"})
	require.Equal(t, http.StatusOK, rec.Code)

	rec = api.do(http.MethodGet, "/api/stacks/organization/project/dev", nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		OrgName     string `json:"orgName"`
		ProjectName string `json:"projectName"`
		StackName   string `json:"stackName"`
		Version     int    `json:"version"`
	}
	api.jsonBody(rec, &body)
	assert.Equal(t, "organization", body.OrgName)
	assert.Equal(t, "project", body.ProjectName)
	assert.Equal(t, "dev", body.StackName)
	assert.Equal(t, 0, body.Version)
}

func TestStackHandlers_GetNonExistentStack(t *testing.T) {
	api := newTestAPI(t)
	rec := api.do(http.MethodGet, "/api/stacks/organization/test-project/nonexistent", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestStackHandlers_GetStackShowsActiveUpdate(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/project", map[string]string{"stackName": "dev"})

	rec := api.do(http.MethodPost, "/api/stacks/organization/project/dev/update", map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	require.Equal(t, http.StatusOK, rec.Code)
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	api.jsonBody(rec, &createResp)

	rec = api.do(http.MethodPost, "/api/stacks/organization/project/dev/update/"+createResp.UpdateID, map[string]any{})
	require.Equal(t, http.StatusOK, rec.Code)

	rec = api.do(http.MethodGet, "/api/stacks/organization/project/dev", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	api.jsonBody(rec, &body)
	assert.Equal(t, createResp.UpdateID, body["activeUpdate"])
}

func TestStackHandlers_ImportReturnsCompletedUpdate(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/project", map[string]string{"stackName": "dev"})

	rec := api.do(http.MethodPost, "/api/stacks/organization/project/dev/import", map[string]any{
		"version":    3,
		"deployment": map[string]any{"manifest": map[string]any{"time": "2024-01-01T00:00:00Z"}, "resources": []any{}},
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var importBody struct {
		UpdateID string `json:"updateID"`
	}
	api.jsonBody(rec, &importBody)
	require.NotEmpty(t, importBody.UpdateID)

	rec = api.do(http.MethodGet, "/api/stacks/organization/project/dev/update/"+importBody.UpdateID, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var statusBody struct {
		Status string `json:"status"`
	}
	api.jsonBody(rec, &statusBody)
	assert.Equal(t, "succeeded", statusBody.Status)
}

func TestStackHandlers_LeaseRenewalChangesToken(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/project", map[string]string{"stackName": "dev"})

	rec := api.do(http.MethodPost, "/api/stacks/organization/project/dev/update", map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	require.Equal(t, http.StatusOK, rec.Code)
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	api.jsonBody(rec, &createResp)

	rec = api.do(http.MethodPost, "/api/stacks/organization/project/dev/update/"+createResp.UpdateID, map[string]any{})
	require.Equal(t, http.StatusOK, rec.Code)
	var startBody struct {
		Token           string `json:"token"`
		TokenExpiration int64  `json:"tokenExpiration"`
	}
	api.jsonBody(rec, &startBody)

	rec = api.do(http.MethodPost, "/api/stacks/organization/project/dev/update/"+createResp.UpdateID+"/renew_lease", map[string]any{"duration": 600})
	require.Equal(t, http.StatusOK, rec.Code)
	var renewBody struct {
		Token           string `json:"token"`
		TokenExpiration int64  `json:"tokenExpiration"`
	}
	api.jsonBody(rec, &renewBody)
	assert.NotEqual(t, startBody.Token, renewBody.Token)
	assert.Greater(t, renewBody.TokenExpiration, startBody.TokenExpiration)
}

func TestStackHandlers_EventPagination(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/project", map[string]string{"stackName": "dev"})

	rec := api.do(http.MethodPost, "/api/stacks/organization/project/dev/update", map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	require.Equal(t, http.StatusOK, rec.Code)
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	api.jsonBody(rec, &createResp)

	rec = api.do(http.MethodPost, "/api/stacks/organization/project/dev/update/"+createResp.UpdateID, map[string]any{})
	require.Equal(t, http.StatusOK, rec.Code)

	for i := 1; i <= 5; i++ {
		rec = api.do(http.MethodPost, "/api/stacks/organization/project/dev/update/"+createResp.UpdateID+"/events",
			map[string]any{"sequence": i, "timestamp": 12345 + i, "type": "testEvent"})
		require.Equal(t, http.StatusOK, rec.Code)
	}

	rec = api.do(http.MethodGet, "/api/stacks/organization/project/dev/update/"+createResp.UpdateID+"/events", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var listBody struct {
		Events            []json.RawMessage `json:"events"`
		ContinuationToken *string           `json:"continuationToken"`
	}
	api.jsonBody(rec, &listBody)
	assert.Len(t, listBody.Events, 5)
	require.NotNil(t, listBody.ContinuationToken)

	rec = api.do(http.MethodGet, "/api/stacks/organization/project/dev/update/"+createResp.UpdateID+"/events?continuationToken=3", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var pageBody struct {
		Events []json.RawMessage `json:"events"`
	}
	api.jsonBody(rec, &pageBody)
	assert.Len(t, pageBody.Events, 2)
}

func TestStackHandlers_DeleteNonExistent(t *testing.T) {
	api := newTestAPI(t)
	rec := api.do(http.MethodDelete, "/api/stacks/organization/test-project/nonexistent", nil)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestStackHandlers_Rename(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": "old-name"})

	rec := api.do(http.MethodPost, "/api/stacks/organization/test-project/old-name/rename", map[string]string{"newName": "new-name"})
	assert.Equal(t, http.StatusNoContent, rec.Code)

	rec = api.do(http.MethodGet, "/api/stacks/organization/test-project/old-name", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	rec = api.do(http.MethodGet, "/api/stacks/organization/test-project/new-name", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		StackName string `json:"stackName"`
	}
	api.jsonBody(rec, &body)
	assert.Equal(t, "new-name", body.StackName)
}

func TestStackHandlers_RenameConflict(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": "source"})
	api.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": "target"})

	rec := api.do(http.MethodPost, "/api/stacks/organization/test-project/source/rename", map[string]string{"newName": "target"})
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), "a stack with that name already exists")
}

func TestStackHandlers_Tags(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": "dev"})

	rec := api.do(http.MethodPatch, "/api/stacks/organization/test-project/dev/tags", map[string]string{"env": "production", "team": "platform"})
	assert.Equal(t, http.StatusNoContent, rec.Code)

	rec = api.do(http.MethodGet, "/api/stacks/organization/test-project/dev", nil)
	var body struct {
		Tags map[string]string `json:"tags"`
	}
	api.jsonBody(rec, &body)
	assert.Equal(t, "production", body.Tags["env"])
	assert.Equal(t, "platform", body.Tags["team"])

	// Replace all tags.
	api.do(http.MethodPatch, "/api/stacks/organization/test-project/dev/tags", map[string]string{"env": "staging"})
	rec = api.do(http.MethodGet, "/api/stacks/organization/test-project/dev", nil)
	var body2 struct {
		Tags map[string]string `json:"tags"`
	}
	api.jsonBody(rec, &body2)
	assert.Equal(t, "staging", body2.Tags["env"])
	assert.Empty(t, body2.Tags["team"])
}

func TestStackHandlers_ExportFreshStack(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": "empty"})

	rec := api.do(http.MethodGet, "/api/stacks/organization/test-project/empty/export", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"deployment"`)
}

func TestStackHandlers_UserStacksFilterByProject(t *testing.T) {
	api := newTestAPI(t)

	for _, project := range []string{"alpha", "beta"} {
		for _, stack := range []string{"dev", "prod"} {
			api.do(http.MethodPost, "/api/stacks/organization/"+project, map[string]string{"stackName": stack})
		}
	}

	rec := api.do(http.MethodGet, "/api/user/stacks?organization=organization&project=alpha", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var listResp struct {
		Stacks []struct {
			ProjectName string `json:"projectName"`
			StackName   string `json:"stackName"`
		} `json:"stacks"`
	}
	api.jsonBody(rec, &listResp)
	assert.Len(t, listResp.Stacks, 2)
	for _, s := range listResp.Stacks {
		assert.Equal(t, "alpha", s.ProjectName)
	}
}

func TestStackHandlers_OrgStacksListing(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/project-a", map[string]string{"stackName": "dev"})
	api.do(http.MethodPost, "/api/stacks/organization/project-b", map[string]string{"stackName": "prod"})

	rec := api.do(http.MethodGet, "/api/stacks/organization", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var listResp struct {
		Stacks []struct {
			OrgName     string `json:"orgName"`
			ProjectName string `json:"projectName"`
		} `json:"stacks"`
	}
	api.jsonBody(rec, &listResp)
	assert.Len(t, listResp.Stacks, 2)
	for _, s := range listResp.Stacks {
		assert.Equal(t, "organization", s.OrgName)
	}
}

func TestStackHandlers_EncryptDecrypt(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": "dev"})

	plaintext := []byte("hello-secret-world")
	b64 := base64.StdEncoding.EncodeToString(plaintext)

	rec := api.do(http.MethodPost, "/api/stacks/organization/test-project/dev/encrypt", map[string]string{"plaintext": b64})
	require.Equal(t, http.StatusOK, rec.Code)
	var encResp struct {
		Ciphertext string `json:"ciphertext"`
	}
	api.jsonBody(rec, &encResp)
	require.NotEmpty(t, encResp.Ciphertext)

	rec = api.do(http.MethodPost, "/api/stacks/organization/test-project/dev/decrypt", map[string]string{"ciphertext": encResp.Ciphertext})
	require.Equal(t, http.StatusOK, rec.Code)
	var decResp struct {
		Plaintext string `json:"plaintext"`
	}
	api.jsonBody(rec, &decResp)

	decoded, err := base64.StdEncoding.DecodeString(decResp.Plaintext)
	require.NoError(t, err)
	assert.Equal(t, string(plaintext), string(decoded))
}

func TestStackHandlers_BatchEncryptDecrypt(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": "dev"})

	pt1 := base64.StdEncoding.EncodeToString([]byte("secret-one"))
	pt2 := base64.StdEncoding.EncodeToString([]byte("secret-two"))

	rec := api.do(http.MethodPost, "/api/stacks/organization/test-project/dev/batch-encrypt", map[string]any{"plaintexts": []string{pt1, pt2}})
	require.Equal(t, http.StatusOK, rec.Code)
	var batchEnc struct {
		Ciphertexts []string `json:"ciphertexts"`
	}
	api.jsonBody(rec, &batchEnc)
	require.Len(t, batchEnc.Ciphertexts, 2)

	rec = api.do(http.MethodPost, "/api/stacks/organization/test-project/dev/batch-decrypt", map[string]any{"ciphertexts": batchEnc.Ciphertexts})
	require.Equal(t, http.StatusOK, rec.Code)
	var batchDec struct {
		Plaintexts map[string]string `json:"plaintexts"`
	}
	api.jsonBody(rec, &batchDec)
	assert.Len(t, batchDec.Plaintexts, 2)
}

func TestStackHandlers_MultipleSecretsReuseKey(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": "dev"})

	secrets := []string{"secret-one", "secret-two", "secret-three"}
	ciphertexts := make([]string, len(secrets))

	for i, s := range secrets {
		b64 := base64.StdEncoding.EncodeToString([]byte(s))
		rec := api.do(http.MethodPost, "/api/stacks/organization/test-project/dev/encrypt", map[string]string{"plaintext": b64})
		require.Equal(t, http.StatusOK, rec.Code)
		var encResp struct {
			Ciphertext string `json:"ciphertext"`
		}
		api.jsonBody(rec, &encResp)
		ciphertexts[i] = encResp.Ciphertext
	}

	for i, ct := range ciphertexts {
		rec := api.do(http.MethodPost, "/api/stacks/organization/test-project/dev/decrypt", map[string]string{"ciphertext": ct})
		require.Equal(t, http.StatusOK, rec.Code)
		var decResp struct {
			Plaintext string `json:"plaintext"`
		}
		api.jsonBody(rec, &decResp)
		decoded, err := base64.StdEncoding.DecodeString(decResp.Plaintext)
		require.NoError(t, err)
		assert.Equal(t, secrets[i], string(decoded), "secret[%d]", i)
	}
}

func TestStackHandlers_SecretsIsolation(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": "stack-a"})
	api.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": "stack-b"})

	plaintext := base64.StdEncoding.EncodeToString([]byte("cross-stack-secret"))
	rec := api.do(http.MethodPost, "/api/stacks/organization/test-project/stack-a/encrypt", map[string]string{"plaintext": plaintext})
	require.Equal(t, http.StatusOK, rec.Code)
	var encResp struct {
		Ciphertext string `json:"ciphertext"`
	}
	api.jsonBody(rec, &encResp)

	// Decrypt with stack-b should fail (different stack key).
	rec = api.do(http.MethodPost, "/api/stacks/organization/test-project/stack-b/decrypt", map[string]string{"ciphertext": encResp.Ciphertext})
	if rec.Code == http.StatusOK {
		var decResp struct {
			Plaintext string `json:"plaintext"`
		}
		api.jsonBody(rec, &decResp)
		decoded, _ := base64.StdEncoding.DecodeString(decResp.Plaintext)
		assert.NotEqual(t, "cross-stack-secret", string(decoded), "cross-stack decryption should fail")
	}
}

func TestStackHandlers_UpdateConfig(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": "dev"})

	rec := api.do(http.MethodPut, "/api/stacks/organization/test-project/dev/config", map[string]any{"key": "value"})
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- helpers for update lifecycle setup ---

type updateSetup struct {
	updateID string
}

func (a *testAPI) createStackAndUpdate(t *testing.T, stack string) updateSetup {
	t.Helper()
	a.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": stack})
	rec := a.do(http.MethodPost, fmt.Sprintf("/api/stacks/organization/test-project/%s/update", stack),
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		UpdateID string `json:"updateID"`
	}
	a.jsonBody(rec, &resp)
	return updateSetup{updateID: resp.UpdateID}
}

func (a *testAPI) startUpdate(t *testing.T, stack, updateID string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = map[string]any{}
	}
	rec := a.do(http.MethodPost, fmt.Sprintf("/api/stacks/organization/test-project/%s/update/%s", stack, updateID), body)
	require.Equal(t, http.StatusOK, rec.Code)
	return rec
}

func (a *testAPI) stackPath(stack string) string {
	return "/api/stacks/organization/test-project/" + stack
}

func (a *testAPI) updatePath(stack, updateID string) string {
	return fmt.Sprintf("/api/stacks/organization/test-project/%s/update/%s", stack, updateID)
}
