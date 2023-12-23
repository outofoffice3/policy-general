package errormgr

import (
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewErrorMgr(t *testing.T) {
	mgr := NewErrorMgr()
	assert.NotNil(t, mgr, "ErrorMgr instance should not be nil")
}

func TestListenForErrorsAndRetrieve(t *testing.T) {
	assertion := assert.New(t)

	// Create an instance of ErrorMgr
	errorMgr := NewErrorMgr().(*_ErrorMgr)
	errorChan := make(chan error)
	errWg := &sync.WaitGroup{}

	// Start listening to the error channel in a goroutine
	errWg.Add(1)
	go func() {
		defer errWg.Done()
		errorMgr.ListenForErrors(errorChan)
	}()

	// Send some errors to the channel
	testError := Error{
		Message:            "test error",
		ResourceType:       "test type",
		ResourceArn:        "test arn",
		PolicyDocumentName: "test policy",
	}
	errorChan <- testError
	errorChan <- Error{
		Message:            "another test error",
		ResourceType:       "test type",
		ResourceArn:        "test arn",
		PolicyDocumentName: "test policy",
	}

	close(errorChan)
	errWg.Wait()

	// Retrieve errors
	errors := errorMgr.GetErrors()
	assertion.Len(errors, 2, "There should be 2 errors stored")
	assertion.Contains(errors, testError, "The specific test error should be present in the stored errors")
}

func TestConcurrentErrorAddition(t *testing.T) {
	assertion := assert.New(t)

	// Create an instance of ErrorMgr
	errorMgr := NewErrorMgr().(*_ErrorMgr)
	errorChan := make(chan error)
	errWg := &sync.WaitGroup{}

	// Start listening to the error channel in a goroutine
	errWg.Add(1)

	go func() {
		defer errWg.Done()
		errorMgr.ListenForErrors(errorChan)
	}()

	// Send errors concurrently
	go func() {
		defer close(errorChan)
		for i := 0; i < 10; i++ {
			errorChan <- Error{
				Message:            "test error " + strconv.Itoa(i),
				ResourceType:       "test type",
				ResourceArn:        "test arn",
				PolicyDocumentName: "test policy",
			}
		}
	}()

	errWg.Wait()

	// Retrieve and check errors
	errors := errorMgr.GetErrors()
	assertion.Len(errors, 10, "There should be 10 errors stored after concurrent addition")
}

func TestNoErrors(t *testing.T) {
	assertion := assert.New(t)

	// Create an instance of ErrorMgr
	errorMgr := NewErrorMgr().(*_ErrorMgr)
	errorChan := make(chan error)
	errWg := &sync.WaitGroup{}

	// Start listening to the error channel in a goroutine
	errWg.Add(1)
	go func() {
		defer errWg.Done()
		errorMgr.ListenForErrors(errorChan)
	}()

	// Do not send any errors
	// Close channel from the test function itself
	close(errorChan)

	errWg.Wait()

	// Retrieve errors
	errors := errorMgr.GetErrors()
	assertion.Empty(errors, "There should be no errors if none were sent")
}
