package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSupportedUpstreamRouteSubsetExistsInOpenAPI(t *testing.T) {
	spec, err := BuildOpenAPISpec()
	require.NoError(t, err)

	tests := []struct {
		path   string
		method string
	}{
		{"/api/capabilities", http.MethodGet},
		{"/api/user", http.MethodGet},
		{"/api/user/stacks", http.MethodGet},
		{"/api/user/organizations/default", http.MethodGet},
		{"/api/stacks/{orgName}", http.MethodGet},
		{"/api/stacks/{orgName}/{projectName}", http.MethodPost},
		{"/api/stacks/{orgName}/{projectName}/{stackName}", http.MethodDelete},
		{"/api/stacks/{orgName}/{projectName}/{stackName}", http.MethodGet},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/export", http.MethodGet},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/import", http.MethodPost},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/encrypt", http.MethodPost},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/decrypt", http.MethodPost},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/updates", http.MethodGet},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/updates/latest", http.MethodGet},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/updates/{version}", http.MethodGet},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/batch-decrypt", http.MethodPost},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/batch-encrypt", http.MethodPost},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/destroy", http.MethodPost},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/preview", http.MethodPost},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/update", http.MethodPost},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}", http.MethodGet},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}", http.MethodPost},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/checkpoint", http.MethodPatch},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/checkpointdelta", http.MethodPatch},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/checkpointverbatim", http.MethodPatch},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/complete", http.MethodPost},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/events", http.MethodPost},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/events/batch", http.MethodPost},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/renew_lease", http.MethodPost},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			item := spec.Paths.Map()[tt.path]
			require.NotNil(t, item, "path missing from OpenAPI")
			assert.NotNil(t, operationForMethod(item, tt.method), "method missing from OpenAPI path item")
		})
	}
}

func TestSupportedOpenAPIOperationIDs(t *testing.T) {
	spec, err := BuildOpenAPISpec()
	require.NoError(t, err)

	tests := []struct {
		path        string
		method      string
		operationID string
	}{
		{"/api/capabilities", http.MethodGet, "getCapabilities"},
		{"/api/user", http.MethodGet, "getUser"},
		{"/api/user/stacks", http.MethodGet, "listUserStacks"},
		{"/api/stacks/{orgName}/{projectName}", http.MethodPost, "createStack"},
		{"/api/stacks/{orgName}/{projectName}/{stackName}", http.MethodGet, "getStack"},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/rename", http.MethodPost, "renameStack"},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/export", http.MethodGet, "exportStack"},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/import", http.MethodPost, "importStack"},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}", http.MethodGet, "getUpdateStatus"},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}", http.MethodPost, "startUpdate"},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/checkpoint", http.MethodPatch, "patchCheckpoint"},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/complete", http.MethodPost, "completeUpdate"},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/events", http.MethodGet, "getEvents"},
		{"/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/events", http.MethodPost, "postEvent"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			item := spec.Paths.Map()[tt.path]
			require.NotNil(t, item)
			op := operationForMethod(item, tt.method)
			require.NotNil(t, op)
			assert.Equal(t, tt.operationID, op.OperationID)
		})
	}
}

func TestCompatibilityErrorShape(t *testing.T) {
	api := newTestAPI(t)

	tests := []struct {
		name           string
		method         string
		path           string
		body           any
		authHeader     string
		wantStatusCode int
		wantMessage    string
	}{
		{
			name:           "missing auth header",
			method:         http.MethodGet,
			path:           "/api/user",
			authHeader:     "",
			wantStatusCode: http.StatusUnauthorized,
			wantMessage:    "missing Authorization header",
		},
		{
			name:           "invalid auth header format",
			method:         http.MethodGet,
			path:           "/api/user",
			authHeader:     "Bearer no",
			wantStatusCode: http.StatusUnauthorized,
			wantMessage:    "invalid Authorization header format",
		},
		{
			name:           "invalid continuation token",
			method:         http.MethodGet,
			path:           "/api/stacks/organization/project/dev/update/missing/events?continuationToken=bad",
			authHeader:     "token test-token",
			wantStatusCode: http.StatusNotFound,
			wantMessage:    "update not found",
		},
		{
			name:           "import missing body",
			method:         http.MethodPost,
			path:           "/api/stacks/organization/project/dev/import",
			authHeader:     "token test-token",
			wantStatusCode: http.StatusBadRequest,
			wantMessage:    "request body is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := api.doWithAuth(tt.method, tt.path, tt.body, tt.authHeader)
			assert.Equal(t, tt.wantStatusCode, rec.Code)

			var payload map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
			assert.Equal(t, float64(tt.wantStatusCode), payload["code"])
			assert.Equal(t, tt.wantMessage, payload["message"])
		})
	}
}

func TestCompatibilityFlow_CreateUpdateCheckpointCompleteExport(t *testing.T) {
	api := newTestAPI(t)

	rec := api.do(http.MethodPost, "/api/stacks/organization/project", map[string]string{"stackName": "dev"})
	require.Equal(t, http.StatusOK, rec.Code)

	rec = api.do(http.MethodPost, "/api/stacks/organization/project/dev/update", map[string]any{
		"config":   map[string]any{},
		"metadata": map[string]any{},
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	api.jsonBody(rec, &createResp)
	require.NotEmpty(t, createResp.UpdateID)

	rec = api.do(http.MethodPost, "/api/stacks/organization/project/dev/update/"+createResp.UpdateID, map[string]any{})
	require.Equal(t, http.StatusOK, rec.Code)
	var startResp struct {
		Token string `json:"token"`
	}
	api.jsonBody(rec, &startResp)
	require.NotEmpty(t, startResp.Token)

	rec = api.do(http.MethodPatch, "/api/stacks/organization/project/dev/update/"+createResp.UpdateID+"/checkpoint", map[string]any{
		"version": 3,
		"deployment": map[string]any{
			"manifest":  map[string]any{"time": "2024-01-01T00:00:00Z"},
			"resources": []any{},
		},
	})
	require.Equal(t, http.StatusOK, rec.Code)

	rec = api.do(http.MethodPost, "/api/stacks/organization/project/dev/update/"+createResp.UpdateID+"/complete", map[string]any{
		"status": "succeeded",
		"result": map[string]any{},
	})
	require.Equal(t, http.StatusOK, rec.Code)

	rec = api.do(http.MethodGet, "/api/stacks/organization/project/dev/update/"+createResp.UpdateID, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var statusResp struct {
		Status string `json:"status"`
	}
	api.jsonBody(rec, &statusResp)
	assert.Equal(t, "succeeded", statusResp.Status)

	rec = api.do(http.MethodGet, "/api/stacks/organization/project/dev/export", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"deployment"`)
}

func TestCompatibilityNegativeMethodsOnSupportedRoutes(t *testing.T) {
	api := newTestAPI(t)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodPut, "/api/capabilities"},
		{http.MethodPut, "/api/stacks/organization/project"},
		{http.MethodDelete, "/api/stacks/organization/project/dev/export"},
		{http.MethodPatch, "/api/user"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			rec := api.do(tt.method, tt.path, nil)
			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		})
	}
}

func TestCompatibilityInvalidEventsContinuationTokenErrorShape(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/project", map[string]string{"stackName": "dev"})

	rec := api.do(http.MethodPost, "/api/stacks/organization/project/dev/update", map[string]any{
		"config":   map[string]any{},
		"metadata": map[string]any{},
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	api.jsonBody(rec, &createResp)

	rec = api.do(http.MethodGet, "/api/stacks/organization/project/dev/update/"+createResp.UpdateID+"/events?continuationToken=bad", nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, float64(http.StatusBadRequest), payload["code"])
	assert.Equal(t, "invalid continuation token", payload["message"])
}

func TestCompatibilityInvalidGzipBodyErrorShape(t *testing.T) {
	srv := newSQLiteTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/stacks/organization/project", bytes.NewReader([]byte("not-gzip")))
	req.Header.Set("Authorization", "token test-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, float64(http.StatusBadRequest), payload["code"])
	assert.Equal(t, "invalid gzip body", payload["message"])
}

func operationForMethod(item *openapi3.PathItem, method string) *openapi3.Operation {
	switch method {
	case http.MethodGet:
		return item.Get
	case http.MethodPost:
		return item.Post
	case http.MethodPut:
		return item.Put
	case http.MethodPatch:
		return item.Patch
	case http.MethodDelete:
		return item.Delete
	case http.MethodHead:
		return item.Head
	default:
		return nil
	}
}
