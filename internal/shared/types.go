package shared

import (
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

type AwsConfigCompliance string
type ResourceType string
type EnvVar string
type S3BucketName string
type S3ObjectKey string
type AwsRegion string

type CheckNoAccessConfig struct {
	Cfg       aws.Config
	Config    Config
	AccountId string
}

type InvokingEvent struct {
	AWSAccountId             string `json:"awsAccountId"`
	NotificationCreationTime string `json:"notificationCreationTime"`
	MessageType              string `json:"messageType"`
	RecordVersion            string `json:"recordVersion"`
}

type ComplianceResult struct {
	Compliance         configServiceTypes.ComplianceType   `json:"compliance"`
	Reasons            []accessAnalyzerTypes.ReasonSummary `json:"reasons"`
	Message            string                              `json:"message"`
	PolicyDocumentName string                              `json:"policyDocumentName"`
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
	RestrictedActions []string     `json:"restrictedActions"`
	Scope             string       `json:"scope"`
}

// AWSAccount represents an AWS account with its associated IAM role.
type AWSAccount struct {
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
}

func JoinReasons(reasons []accessAnalyzerTypes.ReasonSummary, separator string) string {
	var reasonsStrs []string
	if reasons == nil {
		log.Println("reasons null. returning empty strings")
		return ""
	}
	for _, reason := range reasons {
		reasonsStrs = append(reasonsStrs, *reason.Description)
	}
	return strings.Join(reasonsStrs, separator)
}
