package errormgr

import (
	"encoding/csv"
	"fmt"
	"os"
	"sync"

	"github.com/outofoffice3/policy-general/internal/awsclientmgr"
)

// Error defines the structure of an error that can be reported.
type Error struct {
	AccountId          string
	ResourceType       string
	PolicyDocumentName string
	Message            string
}

func (e Error) Error() string {
	return ""
}

// ErrorMgr defines the interface for an error reporting service.
type ErrorMgr interface {
	// StoreError stores an error for later reporting in a thread-safe manner.
	StoreError(err Error)

	// WriteToCSV writes the stored errors to a CSV file.
	WriteToCSV(filename string) error
}

type NewErrorMgrInput struct {
	AwsClientMgr awsclientmgr.AWSClientMgr
	AccountId    string
}

// New returns a new instance of an ErrorMgr.
func New(input NewErrorMgrInput) ErrorMgr {
	return &_ErrorMgr{
		errors:       make([]Error, 0),
		mu:           &sync.Mutex{},
		awsClientMgr: input.AwsClientMgr,
		accountId:    input.AccountId,
	}
}

type _ErrorMgr struct {
	accountId    string
	errors       []Error
	mu           *sync.Mutex
	awsClientMgr awsclientmgr.AWSClientMgr
}

func (e *_ErrorMgr) StoreError(err Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errors = append(e.errors, err)
}

func (e *_ErrorMgr) WriteToCSV(filename string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV header
	writer.Write([]string{"AccountId", "ResourceType", "PolicyDocumentName", "Message"})

	for _, err := range e.errors {
		record := []string{err.AccountId, err.ResourceType, err.PolicyDocumentName, err.Message}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("error writing to CSV: %w", err)
		}
	}

	return nil
}
