package shared

import (
	"regexp"
	"strings"
)

// validate action from configuration file
func IsValidAction(action string) bool {
	// IAM action pattern: <service-namespace>:<action-name>
	iamActionRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+:[a-zA-Z0-9_\*]+$`)
	return iamActionRegex.MatchString(action)
}

// validate scope
func IsValidScope(scope string) bool {
	if strings.ToLower(scope) == "roles" || strings.ToLower(scope) == "users" || strings.ToLower(scope) == "all" {
		return true
	}
	return false
}

func ValidateAnnotation(str string, maxLength int) string {
	if str != "" {
		return truncateString(str, maxLength)
	}
	return "N/A"
}

func truncateString(str string, maxLength int) string {
	if len(str) > maxLength {
		if maxLength > 3 {
			return str[:maxLength-3] + "..."
		}
		return str[:maxLength]
	}
	return str
}
