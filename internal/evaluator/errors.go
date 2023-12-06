package evaluator

import (
	"log"

	"github.com/outofoffice3/policy-general/internal/shared"
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
	if e.Service != "" {
		return "[" + string(e.Service) + "] : " + e.Message
	}
	return e.Message
}

// errors that occur during the execution of evaluation compliance.  These errors needs to be
// handled carefully since they will occur in its own go routine.
type ProcessingError struct {
	ComplianceEvaluation shared.ComplianceEvaluation
	Result               chan<- shared.ComplianceEvaluation
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
func HandleError(err error, evaluator Evaluator) {
	log.Printf("Error: [%v]", err)
	switch switchErr := err.(type) {
	case InitError:
		{
			// panic and exit applicaiton
			log.Printf("Error type: [%T]\n", switchErr)
			panic(err.Error())
		}
	case GeneralError:
		{
			log.Printf("Error type: [%T]\n", switchErr)
			log.Println(err.Error())
		}
	case ProcessingError:
		{
			log.Println(err.Error())
			resultChannel := err.(ProcessingError).Result
			complianceEvaluation := err.(ProcessingError).ComplianceEvaluation
			evaluator.IncrementWaitGroup()        // increment wait group
			resultChannel <- complianceEvaluation // send evaluation to results buffer channel
		}
	default:
		{
			log.Printf("Unknown error: [%v]\n", err)
			log.Printf("Error type: [%T]\n", switchErr)
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
