package entrymgr

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/configservice/types"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/policy-general/internal/shared"
	"github.com/stretchr/testify/assert"
)

func TestEntryMgr(t *testing.T) {
	assertion := assert.New(t)

	em := Init()
	assertion.NotNil(em)

	// ####################################
	// CREATE NEW ENTRY MGR
	// ####################################
	em = Init()
	assertion.NotNil(em)

	// ####################################
	// ADD TO ENTRY MGR
	// ####################################

	insufficientData := shared.ExecutionLogEntry{
		AccountId:    "",
		ResourceType: string(shared.AwsIamRole),
		Compliance:   string(types.ComplianceTypeInsufficientData),
		Reasons:      "",
		Message:      "",
		Arn:          "",
		ErrMsg:       "",
		Timestamp:    time.Now().Format(time.RFC3339),
	}
	err := em.Add(insufficientData)
	assertion.NoError(err)

	nonCompliant := shared.ExecutionLogEntry{
		AccountId:    "",
		ResourceType: string(shared.AwsIamRole),
		Compliance:   string(types.ComplianceTypeNonCompliant),
		Reasons:      "",
		Message:      "",
		Arn:          "",
		ErrMsg:       "",
		Timestamp:    time.Now().Format(time.RFC3339),
	}
	err = em.Add(nonCompliant)
	assertion.NoError(err)

	compliant := shared.ExecutionLogEntry{
		AccountId:    "",
		ResourceType: string(shared.AwsIamRole),
		Compliance:   string(types.ComplianceTypeCompliant),
		Reasons:      "",
		Message:      "",
		Arn:          "",
		ErrMsg:       "",
		Timestamp:    time.Now().Format(time.RFC3339),
	}
	err = em.Add(compliant)
	assertion.NoError(err)

	shouldThrowError := shared.ExecutionLogEntry{
		AccountId:    "",
		ResourceType: string(shared.AwsIamRole),
		Compliance:   string("non-existent-type"),
		Reasons:      "",
		Message:      "",
		Arn:          "",
		ErrMsg:       "",
		Timestamp:    time.Now().Format(time.RFC3339),
	}
	err = em.Add(shouldThrowError)
	assertion.NotNil(shouldThrowError)
	assertion.Error(err)

	// ####################################
	// GET FROM ENTRY MGR
	// ####################################
	entries, err := em.GetEntries(string(types.ComplianceTypeInsufficientData))
	assertion.NoError(err)
	assertion.Len(entries, 1)
	assertion.Equal(insufficientData, entries[0])

	entries, err = em.GetEntries(string(types.ComplianceTypeNonCompliant))
	assertion.NoError(err)
	assertion.Len(entries, 1)
	assertion.Equal(nonCompliant, entries[0])

	entries, err = em.GetEntries(string(types.ComplianceTypeCompliant))
	assertion.NoError(err)
	assertion.Len(entries, 1)
	assertion.Equal(compliant, entries[0])

	entries, err = em.GetEntries(string("non-existent-type"))
	assertion.Error(err)
	assertion.Nil(entries)

	evaluation := shared.ComplianceEvaluation{
		AccountId:    "123",
		ResourceType: shared.AwsIamRole,
		Arn:          "123",
		ComplianceResult: shared.ComplianceResult{
			Compliance: configServiceTypes.ComplianceTypeInsufficientData,
			Reasons: []accessAnalyzerTypes.ReasonSummary{
				{
					Description:    aws.String("123"),
					StatementId:    aws.String("1"),
					StatementIndex: aws.Int32(0),
				},
			},
			Message: "test",
		},
	}
	entryResult := CreateExecutionLogEntry(evaluation)
	assertion.Equal("123", entryResult.AccountId)
	assertion.Equal(string(shared.AwsIamRole), entryResult.ResourceType)
	assertion.Equal("123", entryResult.Arn)
	assertion.Equal(string(types.ComplianceTypeInsufficientData), entryResult.Compliance)
	assertion.Equal("123", entryResult.Reasons)
	assertion.Equal("test", entryResult.Message)

}
