package evaluator

import (
	"log"

	"github.com/outofoffice3/policy-general/pkg/pgtypes"
)

type InitError struct {
	message string
}

func (e InitError) Error() string {
	return e.message
}

type ExecutionError struct {
	service AwsServiceName
	message string
}

func (e ExecutionError) Error() string {
	return "[" + string(e.service) + "] : " + e.message
}

type ProcessingError struct {
	complianceEvaluation pgtypes.ComplianceEvaluation
	result               chan<- pgtypes.ComplianceEvaluation
	message              string
}

func (e ProcessingError) Error() string {
	return e.message
}

type EvaluationError struct {
	message string
}

func (e EvaluationError) Error() string {
	return e.message
}

// error handler
func handleError(err error) {
	log.Printf("Error: [%v]", err)
	switch err.(type) {
	case InitError:
		{
		}
	case ExecutionError:
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
