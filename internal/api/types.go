package api

import (
	"encoding/json"
)

// --- Path param mixins ---

// OrgParams contains the org path parameter.
type OrgParams struct {
	OrgName string `path:"orgName" doc:"Organization name"`
}

// StackParams contains the standard stack path parameters.
type StackParams struct {
	OrgName     string `path:"orgName" doc:"Organization name"`
	ProjectName string `path:"projectName" doc:"Project name"`
	StackName   string `path:"stackName" doc:"Stack name"`
}

// UpdateParams contains the standard update path parameters.
type UpdateParams struct {
	OrgName     string `path:"orgName" doc:"Organization name"`
	ProjectName string `path:"projectName" doc:"Project name"`
	StackName   string `path:"stackName" doc:"Stack name"`
	UpdateKind  string `path:"updateKind" doc:"Update kind (preview, update, refresh, destroy)"`
	UpdateID    string `path:"updateID" doc:"Update ID"`
}

// --- Reusable sub-types for schema precision ---

// Capability represents a single backend capability.
type Capability struct {
	Capability    string          `json:"capability"`
	Version       int             `json:"version,omitempty"`
	Configuration json.RawMessage `json:"configuration,omitempty"`
}

// ConfigValue represents a single config key entry in an update request.
type ConfigValue struct {
	String string `json:"string"`
	Secret bool   `json:"secret"`
	Object bool   `json:"object,omitempty"`
}

// UpdateMetadata describes metadata sent with an update request.
type UpdateMetadata struct {
	Message     string            `json:"message,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

// StackConfig describes stack-level secrets/encryption configuration.
type StackConfig struct {
	Environment     string `json:"environment,omitempty"`
	SecretsProvider string `json:"secretsProvider,omitempty"`
	EncryptedKey    string `json:"encryptedKey,omitempty"`
	EncryptionSalt  string `json:"encryptionSalt,omitempty"`
}

// UpdateOptions describes options for an update request.
type UpdateOptions struct {
	AutoApprove          bool   `json:"autoApprove,omitempty"`
	Color                string `json:"color,omitempty"`
	DryRun               bool   `json:"dryRun,omitempty"`
	Parallel             int    `json:"parallel,omitempty"`
	ShowConfig           bool   `json:"showConfig,omitempty"`
	ShowReplacementSteps bool   `json:"showReplacementSteps,omitempty"`
	ShowSames            bool   `json:"showSames,omitempty"`
	ShowReads            bool   `json:"showReads,omitempty"`
}

// UntypedDeployment represents an untyped deployment object.
type UntypedDeployment struct {
	Version    int            `json:"version,omitempty"`
	Deployment map[string]any `json:"deployment,omitempty"`
}

// TokenInfo describes the current API token.
type TokenInfo struct {
	Name string `json:"name"`
}

// Message is a generic message object from the API.
type Message struct {
	Message string `json:"message,omitempty"`
}

// RequiredPolicy describes a required policy pack.
type RequiredPolicy struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// StackSummary is a stack entry in list responses.
type StackSummary struct {
	OrgName       string            `json:"orgName"`
	ProjectName   string            `json:"projectName"`
	StackName     string            `json:"stackName"`
	LastUpdate    int64             `json:"lastUpdate,omitempty"`
	ResourceCount int               `json:"resourceCount"`
	Tags          map[string]string `json:"tags,omitempty"`
}

// UpdateInfo describes metadata about an update in history responses.
type UpdateInfo struct {
	Kind            string            `json:"kind"`
	Result          string            `json:"result"`
	Message         string            `json:"message"`
	Version         int               `json:"version"`
	StartTime       int64             `json:"startTime"`
	EndTime         *int64            `json:"endTime,omitempty"`
	ResourceChanges json.RawMessage   `json:"resourceChanges,omitempty"`
	Environment     map[string]string `json:"environment,omitempty"`
	Config          map[string]any    `json:"config,omitempty"`
}

// RequestedBy identifies who initiated an update.
type RequestedBy struct {
	Name        string `json:"name"`
	GitHubLogin string `json:"githubLogin"`
	AvatarURL   string `json:"avatarUrl"`
}

// UpdateSummary is an update entry in history list responses.
// Identical to UpdateInfo — defined as a type alias for clarity.
type UpdateSummary = UpdateInfo

// --- Capabilities ---

type GetCapabilitiesOutput struct {
	Body struct {
		Capabilities []Capability `json:"capabilities"`
	}
}

type GetCLIVersionOutput struct {
	Body struct {
		LatestVersion        string `json:"latestVersion"`
		OldestWithoutWarning string `json:"oldestWithoutWarning"`
		LatestDevVersion     string `json:"latestDevVersion"`
	}
}

// --- User ---

type GetUserOutput struct {
	Body struct {
		GitHubLogin   string     `json:"githubLogin"`
		Name          string     `json:"name"`
		AvatarURL     string     `json:"avatarUrl"`
		Organizations []any      `json:"organizations"`
		Identities    []string   `json:"identities"`
		SiteAdmin     bool       `json:"siteAdmin"`
		TokenInfo     *TokenInfo `json:"tokenInfo"`
	}
}

type GetDefaultOrgOutput struct {
	Body struct {
		GitHubLogin string    `json:"GitHubLogin"`
		Messages    []Message `json:"Messages"`
	}
}

type ListUserStacksInput struct {
	Organization      string `query:"organization" doc:"Filter by organization"`
	Project           string `query:"project" doc:"Filter by project"`
	TagName           string `query:"tagName" doc:"Filter by tag name"`
	TagValue          string `query:"tagValue" doc:"Filter by tag value"`
	MaxResults        int    `query:"maxResults" doc:"Maximum results per page"`
	RoleID            string `query:"roleID" doc:"Filter by role ID"`
	ContinuationToken string `query:"continuationToken" doc:"Pagination continuation token"`
}

type ListUserStacksOutput struct {
	Body struct {
		Stacks            []StackSummary `json:"stacks"`
		ContinuationToken *string        `json:"continuationToken,omitempty"`
	}
}

type ListOrgStacksInput struct {
	OrgParams
	ContinuationToken string `query:"continuationToken" doc:"Pagination continuation token"`
}

type ListOrgStacksOutput struct {
	Body struct {
		Stacks            []StackSummary `json:"stacks"`
		ContinuationToken *string        `json:"continuationToken,omitempty"`
	}
}

// --- Stacks ---

type ProjectExistsInput struct {
	OrgName     string `path:"orgName" doc:"Organization name"`
	ProjectName string `path:"projectName" doc:"Project name"`
}

type CreateStackInput struct {
	OrgName     string `path:"orgName" doc:"Organization name"`
	ProjectName string `path:"projectName" doc:"Project name"`
	Body        struct {
		StackName string             `json:"stackName"`
		Tags      map[string]string  `json:"tags,omitempty"`
		Teams     []string           `json:"teams,omitempty"`
		Config    *StackConfig       `json:"config,omitempty"`
		State     *UntypedDeployment `json:"state,omitempty"`
	}
}

type CreateStackOutput struct {
	Body struct{}
}

type GetStackInput struct {
	StackParams
}

type GetStackOutput struct {
	Body struct {
		OrgName      string            `json:"orgName"`
		ProjectName  string            `json:"projectName"`
		StackName    string            `json:"stackName"`
		Tags         map[string]string `json:"tags"`
		Version      int               `json:"version"`
		ActiveUpdate *string           `json:"activeUpdate,omitempty"`
	}
}

type DeleteStackInput struct {
	StackParams
	Force bool `query:"force" doc:"Force delete even if stack has resources"`
}

type UpdateStackTagsInput struct {
	StackParams
	Body map[string]string
}

type RenameStackInput struct {
	StackParams
	Body struct {
		NewName    string `json:"newName"`
		NewProject string `json:"newProject"`
	}
}

// --- State Export/Import ---

type ExportStackInput struct {
	StackParams
}

type ExportStackVersionInput struct {
	StackParams
	Version int `path:"version" doc:"State version number"`
}

type ImportStackInput struct {
	StackParams
	RawBody []byte
}

type ImportStackOutput struct {
	Body struct {
		UpdateID string `json:"updateId"`
	}
}

// --- Secrets ---

type EncryptValueInput struct {
	StackParams
	Body struct {
		Plaintext []byte `json:"plaintext"`
	}
}

type EncryptValueOutput struct {
	Body struct {
		Ciphertext []byte `json:"ciphertext"`
	}
}

type DecryptValueInput struct {
	StackParams
	Body struct {
		Ciphertext []byte `json:"ciphertext"`
	}
}

type DecryptValueOutput struct {
	Body struct {
		Plaintext []byte `json:"plaintext"`
	}
}

type BatchEncryptInput struct {
	StackParams
	Body struct {
		Plaintexts [][]byte `json:"plaintexts"`
	}
}

type BatchEncryptOutput struct {
	Body struct {
		Ciphertexts [][]byte `json:"ciphertexts"`
	}
}

type BatchDecryptInput struct {
	StackParams
	Body struct {
		Ciphertexts [][]byte `json:"ciphertexts"`
	}
}

type BatchDecryptOutput struct {
	Body struct {
		Plaintexts map[string][]byte `json:"plaintexts"`
	}
}

// --- Update Lifecycle ---

type CreateUpdateInput struct {
	StackParams
	RawBody []byte
	Body    struct {
		Name        string                 `json:"name,omitempty"`
		Description string                 `json:"description,omitempty"`
		Main        string                 `json:"main,omitempty"`
		Runtime     string                 `json:"runtime,omitempty"`
		Options     *UpdateOptions         `json:"options,omitempty"`
		Config      map[string]ConfigValue `json:"config,omitempty"`
		Metadata    *UpdateMetadata        `json:"metadata,omitempty"`
	}
}

type CreateUpdateOutput struct {
	Body struct {
		UpdateID         string           `json:"updateID"`
		RequiredPolicies []RequiredPolicy `json:"requiredPolicies"`
		Messages         []Message        `json:"messages"`
	}
}

type StartUpdateInput struct {
	UpdateParams
	Body struct {
		Tags           map[string]string `json:"tags"`
		JournalVersion int               `json:"journalVersion"`
	}
}

type StartUpdateOutput struct {
	Body struct {
		Version         int    `json:"version"`
		Token           string `json:"token"`
		TokenExpiration int64  `json:"tokenExpiration"`
		JournalVersion  int    `json:"journalVersion"`
	}
}

type GetUpdateStatusInput struct {
	UpdateParams
}

type GetUpdateStatusOutput struct {
	Body struct {
		Status            string  `json:"status"`
		Events            []any   `json:"events"`
		ContinuationToken *string `json:"continuationToken,omitempty"`
	}
}

type CompleteUpdateInput struct {
	UpdateParams
	Body struct {
		Status string          `json:"status"`
		Result json.RawMessage `json:"result"`
	}
}

type RenewLeaseInput struct {
	UpdateParams
	Body struct {
		Token    string `json:"token"`
		Duration int    `json:"duration"`
	}
}

type RenewLeaseOutput struct {
	Body struct {
		Token           string `json:"token"`
		TokenExpiration int64  `json:"tokenExpiration"`
	}
}

type CancelUpdateInput struct {
	StackParams
}

// --- Checkpoints ---

type PatchCheckpointInput struct {
	UpdateParams
	Body struct {
		IsInvalid  bool            `json:"isInvalid"`
		Version    int             `json:"version"`
		Features   []string        `json:"features,omitempty"`
		Deployment json.RawMessage `json:"deployment"`
	}
}

type PatchCheckpointVerbatimInput struct {
	UpdateParams
	Body struct {
		Version           int             `json:"version"`
		UntypedDeployment json.RawMessage `json:"untypedDeployment"`
		SequenceNumber    int             `json:"sequenceNumber"`
	}
}

type PatchCheckpointDeltaInput struct {
	UpdateParams
	Body struct {
		Version         int    `json:"version"`
		CheckpointHash  string `json:"checkpointHash"`
		SequenceNumber  int    `json:"sequenceNumber"`
		DeploymentDelta string `json:"deploymentDelta"`
	}
}

// --- Journal Entries ---

type SaveJournalEntriesInput struct {
	UpdateParams
	RawBody []byte
}

// --- Engine Events ---

type PostEventInput struct {
	UpdateParams
	RawBody []byte
}

type PostEventsBatchInput struct {
	UpdateParams
	Body struct {
		Events []json.RawMessage `json:"events"`
	}
}

type GetEventsInput struct {
	UpdateParams
	ContinuationToken string `query:"continuationToken" doc:"Offset into events"`
}

type GetEventsOutput struct {
	Body struct {
		Status            string            `json:"status"`
		Events            []json.RawMessage `json:"events"`
		ContinuationToken *string           `json:"continuationToken,omitempty"`
	}
}

// --- History ---

type GetUpdatesInput struct {
	StackParams
	PageSize   int    `query:"pageSize" doc:"Number of updates per page"`
	Page       int    `query:"page" doc:"Page number"`
	OutputType string `query:"output-type" doc:"Output type format"`
}

type GetUpdatesOutput struct {
	Body struct {
		Updates []UpdateSummary `json:"updates"`
	}
}

type GetLatestUpdateInput struct {
	StackParams
}

type GetLatestUpdateOutput struct {
	Body struct {
		Info          UpdateInfo  `json:"info"`
		UpdateID      string      `json:"updateID"`
		Version       int         `json:"version"`
		LatestVersion int         `json:"latestVersion"`
		RequestedBy   RequestedBy `json:"requestedBy"`
	}
}

type GetUpdateByVersionInput struct {
	StackParams
	Version int `path:"version" doc:"Update version number"`
}

type GetUpdateByVersionOutput struct {
	Body struct {
		Info          UpdateInfo  `json:"info"`
		UpdateID      string      `json:"updateID"`
		Version       int         `json:"version"`
		LatestVersion int         `json:"latestVersion"`
		RequestedBy   RequestedBy `json:"requestedBy"`
	}
}

// --- Stack Config ---

type GetStackConfigInput struct {
	StackParams
}

type GetStackConfigOutput struct {
	Body StackConfig
}

type UpdateStackConfigInput struct {
	StackParams
	Body StackConfig
}

// --- Health check ---

type HealthCheckOutput struct {
	Body struct {
		Status string `json:"status"`
	}
}

// --- Auth ---

type GoogleTokenExchangeInput struct {
	Body struct {
		IDToken string `json:"idToken"`
	}
}

type GoogleTokenExchangeOutput struct {
	Body struct {
		Token     string `json:"accessToken"` //nolint:gosec // JSON API field, not a credential
		UserName  string `json:"userName"`
		ExpiresAt int64  `json:"expiresAt"`
	}
}

// --- Admin ---

type CreateBackupOutput struct {
	Body struct {
		Path string `json:"path"`
	}
}

// RevokeUserTokensInput is the path parameter for revoking a user's tokens.
type RevokeUserTokensInput struct {
	UserName string `path:"userName" doc:"User whose tokens to revoke"`
}

// RevokeUserTokensOutput is the response from revoking a user's tokens.
type RevokeUserTokensOutput struct {
	Body struct {
		Revoked int64 `json:"revoked" doc:"Number of tokens revoked"`
	}
}

// ListUserTokensInput is the path parameter for listing a user's tokens.
type ListUserTokensInput struct {
	UserName string `path:"userName" doc:"User whose tokens to list"`
}

// AdminTokenInfo is a summary of a stored token (no secrets exposed).
type AdminTokenInfo struct {
	TokenHashPrefix string `json:"tokenHashPrefix" doc:"First 8 chars of the token hash"`
	Description     string `json:"description"`
	CreatedAt       int64  `json:"createdAt"`
	LastUsedAt      *int64 `json:"lastUsedAt,omitempty"`
	ExpiresAt       *int64 `json:"expiresAt,omitempty"`
	HasRefreshToken bool   `json:"hasRefreshToken" doc:"Whether a Google refresh token is stored"`
}

// ListUserTokensOutput is the response listing a user's tokens.
type ListUserTokensOutput struct {
	Body struct {
		Tokens []AdminTokenInfo `json:"tokens"`
	}
}
