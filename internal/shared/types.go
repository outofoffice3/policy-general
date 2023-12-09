package shared

import (
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

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

type ComplianceEvaluation struct {
	AccountId        string           `json:"accountId"`
	ResourceType     ResourceType     `json:"resoucetype"`
	Arn              string           `json:"arn"`
	ComplianceResult ComplianceResult `json:"complianceResult"`
	ErrMsg           string           `json:"errMsg"`
	Timestamp        time.Time        `json:"timestamp"`
}

type ComplianceResult struct {
	Compliance types.ComplianceType                `json:"compliance"`
	Reasons    []accessAnalyzerTypes.ReasonSummary `json:"reasons"`
	Message    string                              `json:"message"`
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

type ConfigEvent struct {
	Version          string `json:"version"`
	InvokingEvent    string `json:"invokingEvent"`
	RuleParameters   string `json:"ruleParameters"`
	ResultToken      string `json:"resultToken"`
	EventLeftScope   bool   `json:"eventLeftScope"`
	ExecutionRoleArn string `json:"executionRoleArn"`
	ConfigRuleArn    string `json:"configRuleArn"`
	ConfigRuleName   string `json:"configRuleName"`
	ConfigRuleID     string `json:"configRuleId"`
	AccountID        string `json:"accountId"`
	EvaluationMode   string `json:"evaluationMode"`
}

func CreateAWSConfigEvaluation(evaluation ComplianceEvaluation) configServiceTypes.Evaluation {
	reasons := JoinReasons(evaluation.ComplianceResult.Reasons, ";")
	e := configServiceTypes.Evaluation{
		ComplianceResourceType: aws.String(string(evaluation.ResourceType)),
		ComplianceResourceId:   aws.String(evaluation.Arn),
		ComplianceType:         evaluation.ComplianceResult.Compliance,
		OrderingTimestamp:      aws.Time(evaluation.Timestamp),
	}
	// if there was an error, set the annotation to the error message
	if evaluation.ErrMsg != "" {
		e.Annotation = aws.String(evaluation.ErrMsg)
	}
	// if there was a non-empty reason, set the annotation to the reason
	if reasons != "" {
		e.Annotation = aws.String(reasons)
	}
	return e
}

func JoinReasons(reasons []accessAnalyzerTypes.ReasonSummary, separator string) string {
	var reasonsStrs []string
	for _, reason := range reasons {
		reasonsStrs = append(reasonsStrs, *reason.Description)
		// You can include other fields from ReasonSummary if needed
	}
	return strings.Join(reasonsStrs, separator)
}
