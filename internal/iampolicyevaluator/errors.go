package iampolicyevaluator

import (
	"log"

	"github.com/outofoffice3/policy-general/internal/shared"
)

// errors that occur during the execution of evaluation compliance.  These errors needs to be
// handled carefully since they will occur in its own go routine.
type ProcessingError struct {
	ComplianceEvaluation shared.ComplianceEvaluation
	ResultsBuffer        chan<- shared.ComplianceEvaluation
	Message              string
}

func (e ProcessingError) Error() string {
	return e.Message
}

// error handler
func HandleError(err error, evaluator IAMPolicyEvaluator) {
	log.Printf("Error: [%v]", err)
	switch switchErr := err.(type) {
	case ProcessingError:
		{
			log.Println(err.Error())
			resultChannel := err.(ProcessingError).ResultsBuffer
			complianceEvaluation := err.(ProcessingError).ComplianceEvaluation
			evaluator.IncrementWaitGroup(1)       // increment wait group
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
