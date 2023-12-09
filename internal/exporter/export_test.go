package exporter

import (
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	accessTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/common/logger"
	"github.com/outofoffice3/policy-general/internal/shared"
	"github.com/stretchr/testify/assert"
)

func TestExporter(t *testing.T) {

	// ####################################
	// CREATE NEW EXPORTER
	// ####################################
	assertion := assert.New(t)
	exporter, err := Init(logger.NewConsoleLogger(logger.LogLevelDebug))
	assertion.NoError(err, "should not be an error")
	assertion.NotNil(exporter, "should not be nil")
	exporterAssert := exporter.(*_Exporter)
	assertion.NotNil(exporterAssert.Logger, "should not be nil")
	assertion.NotNil(exporterAssert.entryMgr, "should not be nil")
	assertion.NotNil(exporterAssert.s3Client, "should not be nil")

	// ####################################
	// CREATE NEW EXPORTER (w/o logger CASE)
	// ####################################
	exporter, err = Init(nil)
	assertion.NoError(err, "should not be an error")
	assertion.NotNil(exporter, "should not be nil")
	exporterAssert = exporter.(*_Exporter)
	assertion.NotNil(exporterAssert.Logger, "should not be nil")
	assertion.NotNil(exporterAssert.entryMgr, "should not be nil")
	assertion.NotNil(exporterAssert.s3Client, "should not be nil")

	// ####################################
	// ADD TO EXPORTER
	// ####################################
	exporter, err = Init(logger.NewConsoleLogger(logger.LogLevelDebug))
	assertion.NoError(err, "should not be an error")
	assertion.NotNil(exporter, "should not be nil")

	// INSUFFICIENT DATA RESULT
	err = exporter.AddEntry(shared.ComplianceEvaluation{
		AccountId:    "",
		ResourceType: shared.AWS_IAM_ROLE,
		Arn:          "",
		ComplianceResult: shared.ComplianceResult{
			Compliance: types.ComplianceTypeInsufficientData,
			Reasons:    nil,
			Message:    "",
		},
		ErrMsg:    "",
		Timestamp: time.Now(),
	})
	assertion.NoError(err, "should not be an error")

	// NON COMPLIANT RESULT
	exporter.AddEntry(shared.ComplianceEvaluation{
		AccountId:    "",
		ResourceType: shared.AWS_IAM_ROLE,
		Arn:          "",
		ComplianceResult: shared.ComplianceResult{
			Compliance: types.ComplianceTypeNonCompliant,
			Reasons:    nil,
			Message:    "",
		},
		ErrMsg:    "",
		Timestamp: time.Now(),
	})
	assertion.NoError(err, "should not be an error")

	// COMPLIANT RESULT
	exporter.AddEntry(shared.ComplianceEvaluation{
		AccountId:    "",
		ResourceType: shared.AWS_IAM_ROLE,
		Arn:          "",
		ComplianceResult: shared.ComplianceResult{
			Compliance: types.ComplianceTypeCompliant,
			Reasons:    nil,
			Message:    "",
		},
		ErrMsg:    "",
		Timestamp: time.Now(),
	})
	assertion.NoError(err, "should not be an error")

	err = exporter.WriteToCSV("test.csv")
	assertion.NoError(err, "should not be an error")

	file, err := os.Open("test.csv")
	assertion.NoError(err, "should not be an error")

	key, err := exporter.ExportToS3(shared.CONFIG_FILE_BUCKET_NAME)
	assertion.NoError(err, "should not be an error")
	assertion.NotEmpty(key, "should not be empty")

	file.Close()
	err = os.Remove("test.csv")
	assertion.NoError(err, "should not be an error")

	// ####################################
	// ERRORS VALIDATION
	// ####################################

	key, err = exporter.ExportToS3("non-existent-bucket")
	assertion.Error(err, "should be an error")
	assertion.Empty(key, "should be empty")

	joinReasonsResult := JoinReasons([]accessTypes.ReasonSummary{
		{
			Description:    aws.String("test-description"),
			StatementId:    aws.String("test-statement-id"),
			StatementIndex: aws.Int32(0),
		},

		{
			Description:    aws.String("test-description2"),
			StatementId:    aws.String("test-statement-id2"),
			StatementIndex: aws.Int32(1),
		},
	}, ";")
	assertion.Equal("test-description;test-description2", joinReasonsResult, "should be equal")

}
