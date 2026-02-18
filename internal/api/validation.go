package api

import "fmt"

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
