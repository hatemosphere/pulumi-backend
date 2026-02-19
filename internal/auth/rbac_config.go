package auth

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Permission represents an access level.
type Permission int

const (
	PermissionNone  Permission = iota
	PermissionRead             // read stack state, config, history, events
	PermissionWrite            // create/update stacks, run updates
	PermissionAdmin            // delete stacks, rename, manage access
)

func (p Permission) String() string {
	switch p {
	case PermissionNone:
		return "none"
	case PermissionRead:
		return "read"
	case PermissionWrite:
		return "write"
	case PermissionAdmin:
		return "admin"
	default:
		return "none"
	}
}

// ParsePermission converts a string to a Permission.
func ParsePermission(s string) (Permission, error) {
	switch s {
	case "read":
		return PermissionRead, nil
	case "write":
		return PermissionWrite, nil
	case "admin":
		return PermissionAdmin, nil
	default:
		return PermissionNone, fmt.Errorf("unknown permission: %q", s)
	}
}

// RBACConfig defines group-to-permission mappings loaded from YAML.
type RBACConfig struct {
	DefaultPermission string        `yaml:"defaultPermission"`
	GroupRoles        []GroupRole   `yaml:"groupRoles"`
	StackPolicies     []StackPolicy `yaml:"stackPolicies"`
}

// GroupRole maps a Google Workspace group to a global permission level.
type GroupRole struct {
	Group      string `yaml:"group"`
	Permission string `yaml:"permission"`
}

// StackPolicy maps a group to a permission level for stacks matching a glob pattern.
type StackPolicy struct {
	Group        string `yaml:"group"`
	StackPattern string `yaml:"stackPattern"` // glob: "org/project-pattern/stack-pattern"
	Permission   string `yaml:"permission"`
}

// LoadRBACConfig reads and parses an RBAC configuration file.
func LoadRBACConfig(path string) (*RBACConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rbac config: %w", err)
	}
	var cfg RBACConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse rbac config: %w", err)
	}
	return &cfg, nil
}
