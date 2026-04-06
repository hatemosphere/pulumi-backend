package api

import (
	"fmt"
	"regexp"
)

// validateName checks that a stack or project name is valid.
func validateName(name, kind string) error {
	if len(name) == 0 {
		return fmt.Errorf("%s name is required", kind)
	}
	if len(name) > 100 {
		return fmt.Errorf("%s name too long (max 100 characters)", kind)
	}
	for _, r := range name {
		if !isValidNameChar(r) {
			return fmt.Errorf("%s name contains invalid character: %c", kind, r)
		}
	}
	return nil
}

func isValidNameChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
		r == '-' || r == '_' || r == '.'
}

var stackTagNamePattern = regexp.MustCompile(`^[a-zA-Z0-9\-_.:]{1,40}$`)

func validateStackTags(tags map[string]string) error {
	for key, value := range tags {
		if key == "" {
			return fmt.Errorf("invalid stack tag %q", key)
		}
		if len(key) > 40 {
			return fmt.Errorf("stack tag %q is too long (max length 40 characters)", key)
		}
		if !stackTagNamePattern.MatchString(key) {
			return fmt.Errorf("stack tag names may only contain alphanumerics, hyphens, underscores, periods, or colons")
		}
		if len(value) > 256 {
			return fmt.Errorf("stack tag %q value is too long (max length 256 characters)", key)
		}
	}
	return nil
}
