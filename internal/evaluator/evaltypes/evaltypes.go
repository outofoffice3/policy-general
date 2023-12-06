package evaltypes

import (
	"time"

	accessTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"

	"github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

type AwsConfigCompliance string
type ResourceType string

const (
	COMPLIANT      AwsConfigCompliance = "COMPLIANT"
	NON_COMPLIANT  AwsConfigCompliance = "NON_COMPLIANT"
	NOT_APPLICABLE AwsConfigCompliance = "NOT_APPLICABLE"

	AWS_IAM_ROLE  ResourceType = "AWS::IAM::ROLE"
	AWS_IAM_USER  ResourceType = "AWS::IAM:USER"
	NOT_SPECIFIED ResourceType = "NOT_SPECIFIED"
)

// Config represents the overall configuration structure.
type Config struct {
	AWSAccounts       []AWSAccount `json:"awsAccounts"`
	RestrictedActions []string     `json:"actions"`
	Scope             string       `json:"scope"`
}

// AWSAccount represents an AWS account with its associated IAM role.
type AWSAccount struct {
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
}

type ComplianceEvaluation struct {
	AccountId        string           `json:"accountId"`
	ResourceType     ResourceType     `json:"resoucetype"`
	Arn              string           `json:"arn"`
	ComplianceResult ComplianceResult `json:"complianceResult"`
	Annotation       string           `json:"annotation"`
	ErrMsg           string           `json:"errMsg"`
	Timestamp        time.Time        `json:"timestamp"`
}

type ExecutionLogEntry struct {
	Timestamp    string `json:"timestamp"`
	Compliance   string `json:"compliance"`
	Arn          string `json:"arn"`
	ResourceType string `json:"resourceType"`
	Reasons      string `json:"reasons"`
	Message      string `json:"message"`
	ErrMsg       string `json:"errMsg"`
	AccountId    string `json:"accountId"`
}

type ComplianceResult struct {
	Compliance types.ComplianceType        `json:"compliance"`
	Reasons    []accessTypes.ReasonSummary `json:"reasons"`
	Message    string                      `json:"message"`
}

type AWSConfigEvaluationInput struct {
	ResourceId        string `json:"resourceId"`
	ResourceType      string `json:"resourceType"`
	ComplianceType    string `json:"complianceType"`
	OrderingTimestamp string `json:"orderingTimestamp"`
	Annotation        string `json:"annotation"`
}
