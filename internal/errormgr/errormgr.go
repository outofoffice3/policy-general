package errormgr

// ErrorMgr defines the interface for managing errors.
type ErrorMgr interface {
	ListenForErrors(errorChan <-chan error)
	GetErrors() []error
}

// _ErrorMgr is the implementation of ErrorMgr.
type _ErrorMgr struct {
	errorArray []error
}

type Error struct {
	AccountId          string
	ResourceType       string
	PolicyDocumentName string
	Message            string
	ResourceArn        string
}

func (e Error) Error() string {
	return e.Message
}

// NewErrorMgr creates a new instance of ErrorMgr.
func NewErrorMgr() ErrorMgr {
	return &_ErrorMgr{
		errorArray: make([]error, 0),
	}
}

// ListenForErrors reads errors from the given channel and stores them.
func (em *_ErrorMgr) ListenForErrors(errorChan <-chan error) {
	for err := range errorChan {
		em.errorArray = append(em.errorArray, err)
	}
}

// GetErrors returns all stored errors.
func (em *_ErrorMgr) GetErrors() []error {
	return em.errorArray
}
