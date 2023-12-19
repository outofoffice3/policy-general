package shared

import (
	"context"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

// validate action from configuration file
func IsValidAction(action string) bool {
	// IAM action pattern: <service-namespace>:<action-name>
	iamActionRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+:[a-zA-Z0-9_\*]+$`)
	return iamActionRegex.MatchString(action)
}

// validate scope
func IsValidScope(scope string) bool {
	if strings.ToLower(scope) == "roles" || strings.ToLower(scope) == "users" || strings.ToLower(scope) == "all" {
		return true
	}
	return false
}

func IsCompliant(client *accessanalyzer.Client, policyDocument string, restrictedActions []string) (ComplianceResult, error) {
	input := accessanalyzer.CheckAccessNotGrantedInput{
		Access: []accessAnalyzerTypes.Access{
			{
				Actions: restrictedActions,
			},
		},
		PolicyDocument: aws.String(policyDocument),
		PolicyType:     accessAnalyzerTypes.AccessCheckPolicyTypeIdentityPolicy,
	}
	output, err := client.CheckAccessNotGranted(context.Background(), &input)
	// return errors
	if err != nil {
		return ComplianceResult{}, err
	}
	// check if policy is compliant
	if output.Result == accessAnalyzerTypes.CheckAccessNotGrantedResultPass {
		return ComplianceResult{
			Compliance: configServiceTypes.ComplianceTypeCompliant,
			Reasons:    output.Reasons,
			Message:    *output.Message,
		}, nil
	}
	return ComplianceResult{
		Compliance: configServiceTypes.ComplianceTypeNonCompliant,
		Reasons:    output.Reasons,
		Message:    *output.Message,
	}, nil
}
func ValidateAnnotation(str string, maxLength int) string {
	if str != "" {
		return truncateString(str, maxLength)
	}
	return "N/A"
}

func truncateString(str string, maxLength int) string {
	if len(str) > maxLength {
		if maxLength > 3 {
			return str[:maxLength-3] + "..."
		}
		return str[:maxLength]
	}
	return str
}
