package entrymgr

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/common/logger"
	"github.com/outofoffice3/policy-general/internal/shared"
	"github.com/stretchr/testify/assert"
)

func TestEntryMgr(t *testing.T) {
	assertion := assert.New(t)

	em := Init(nil)
	assertion.NotNil(em)

	// ####################################
	// CREATE NEW ENTRY MGR
	// ####################################
	em = Init(logger.NewConsoleLogger(logger.LogLevelDebug))
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

}
