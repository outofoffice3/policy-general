package entrymgr

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
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

	insufficientData := configServiceTypes.Evaluation{
		ComplianceType:       configServiceTypes.ComplianceTypeInsufficientData,
		ComplianceResourceId: aws.String("insufficientDataEvaluationArn"),
		Annotation:           aws.String(""),
		OrderingTimestamp:    aws.Time(time.Now()),
	}
	err := em.AddEntry(insufficientData)
	assertion.NoError(err)

	nonCompliant := configServiceTypes.Evaluation{
		ComplianceType:       configServiceTypes.ComplianceTypeNonCompliant,
		ComplianceResourceId: aws.String("nonCompliantEvaulationArn"),
		Annotation:           aws.String("noncompliant"),
		OrderingTimestamp:    aws.Time(time.Now()),
	}
	err = em.AddEntry(nonCompliant)
	assertion.NoError(err)

	compliant := configServiceTypes.Evaluation{
		ComplianceType:       configServiceTypes.ComplianceTypeCompliant,
		ComplianceResourceId: aws.String("compliantEvaluationArn"),
		Annotation:           aws.String("compliant"),
		OrderingTimestamp:    aws.Time(time.Now()),
	}
	err = em.AddEntry(compliant)
	assertion.NoError(err)

	notApplicable := configServiceTypes.Evaluation{
		ComplianceType:       configServiceTypes.ComplianceTypeNotApplicable,
		ComplianceResourceId: aws.String("notApplicableEvaluationArn"),
		Annotation:           aws.String("notApplicable"),
		OrderingTimestamp:    aws.Time(time.Now()),
	}
	err = em.AddEntry(notApplicable)
	assertion.NoError(err)

	shouldThrowError := configServiceTypes.Evaluation{
		ComplianceType:       configServiceTypes.ComplianceType("invalid compliance type"),
		ComplianceResourceId: aws.String("shouldThrowErrorEvaluationArn"),
		Annotation:           aws.String(""),
		OrderingTimestamp:    aws.Time(time.Now()),
	}
	err = em.AddEntry(shouldThrowError)
	assertion.NotNil(shouldThrowError)
	assertion.Error(err)

	// ####################################
	// GET FROM ENTRY MGR
	// ####################################
	entries, err := em.GetEntries(string(configServiceTypes.ComplianceTypeInsufficientData))
	assertion.NoError(err)
	assertion.Len(entries, 1)
	assertion.Equal(insufficientData, entries[0])

	entries, err = em.GetEntries(string(configServiceTypes.ComplianceTypeNonCompliant))
	assertion.NoError(err)
	assertion.Len(entries, 1)
	assertion.Equal(nonCompliant, entries[0])

	entries, err = em.GetEntries(string(configServiceTypes.ComplianceTypeCompliant))
	assertion.NoError(err)
	assertion.Len(entries, 1)
	assertion.Equal(compliant, entries[0])

	entries, err = em.GetEntries(string(configServiceTypes.ComplianceTypeNotApplicable))
	assertion.NoError(err)
	assertion.Len(entries, 1)
	assertion.Equal(notApplicable, entries[0])

	entries, err = em.GetEntries(string("non-existent-type"))
	assertion.Error(err)
	assertion.Nil(entries)

}
