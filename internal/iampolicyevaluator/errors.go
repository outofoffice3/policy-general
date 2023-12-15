package iampolicyevaluator

import "github.com/outofoffice3/policy-general/internal/shared"

// errors that occur during the execution of evaluation compliance.  These errors needs to be
// handled carefully since they will occur in its own go routine.
type Error struct {
	AccountId          string
	ResourceType       shared.ResourceType
	PolicyDocumentName string
	Message            string
}

func (e *Error) Error() string {
	return e.Message
}
