package evaluator

import (
	"log"
	"sync"

	"github.com/outofoffice3/policy-general/pkg/evaluator/evaltypes"
)

// errors that occur during initialization
type InitError struct {
	Message string
}

func (e InitError) Error() string {
	return e.Message
}

// default error type.  Can occur anywhere in the program except the initialization phase
type GeneralError struct {
	Service AwsServiceName
	Message string
}

func (e GeneralError) Error() string {
	return "[" + string(e.Service) + "] : " + e.Message
}

// errors that occur during the execution of evaluation compliance.  These errors needs to be
// handled carefully since they will occur in its own go routine.
type ProcessingError struct {
	Wg                   *sync.WaitGroup
	ComplianceEvaluation evaltypes.ComplianceEvaluation
	Result               chan<- evaltypes.ComplianceEvaluation
	Message              string
}

func (e ProcessingError) Error() string {
	return e.Message
}

// errors that occur when trying to send evaluation to AWS Config.  These errors need to be handled
// seperately to allow for unique handling of those failed requests
type EvaluationError struct {
	Message string
}

func (e EvaluationError) Error() string {
	return e.Message
}

// error handler
func HandleError(err error) {
	log.Printf("Error: [%v]", err)
	switch err.(type) {
	case InitError:
		{
		}
	case GeneralError:
		{
		}
	case ProcessingError:
		{
		}
	default:
		{
			log.Printf("Unknown error: [%v]", err)
		}
	}
}

type AwsServiceName string

const (
	S3              AwsServiceName = "s3"
	IAM             AwsServiceName = "iam"
	ACCESS_ANALYZER AwsServiceName = "access analyzer"
	AWS_CONFIG      AwsServiceName = "aws config"
)
