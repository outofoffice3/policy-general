package iampolicyevaluator

import (
	"strings"

	"github.com/outofoffice3/policy-general/internal/shared"
)

// errors that occur during the execution of evaluation compliance.  These errors needs to be
// handled carefully since they will occur in its own go routine.
type Error struct {
	AccountId          string
	ResourceType       shared.ResourceType
	PolicyDocumentName string
	Message            string
}

func (e *Error) Error() string {
	var parts []string

	if e.AccountId != "" {
		parts = append(parts, "AccountId: "+e.AccountId)
	}
	if e.ResourceType != "" {
		parts = append(parts, "ResourceType: "+string(e.ResourceType))
	}
	if e.PolicyDocumentName != "" {
		parts = append(parts, "PolicyDocumentName: "+e.PolicyDocumentName)
	}
	if e.Message != "" {
		parts = append(parts, "Message: "+e.Message)
	}

	return strings.Join(parts, ", ")
}
