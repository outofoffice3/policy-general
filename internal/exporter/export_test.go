package exporter

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/policy-general/internal/awsclientmgr"
	"github.com/outofoffice3/policy-general/internal/entrymgr"
	"github.com/outofoffice3/policy-general/internal/shared"
	"github.com/stretchr/testify/assert"
)

func TestExporter(t *testing.T) {

	// ####################################
	// CREATE NEW EXPORTER
	// ####################################
	assertion := assert.New(t)
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(string(shared.UsEast1)))
	log.Printf("cfg : [%+v] ", cfg)
	assertion.NoError(err, "should not be an error")
	assertion.NotNil(cfg, "should not be nil")

	accountId := "033197602013"
	config := shared.Config{
		AWSAccounts: []shared.AWSAccount{
			{
				AccountID: "017608207428",
				RoleName:  "arn:aws:iam::017608207428:role/checkNoAccessPolicyGeneral2023",
			},
		},
		RestrictedActions: []string{
			"s3:GetObject",
			"s3:PutObject",
			"ec2:DescribeInstances",
			"lambda:InvokeFunction",
		},
		Scope: "all",
	}
	log.Println(config)
	awscmConfig := awsclientmgr.AWSClientMgrInitConfig{
		Cfg:       cfg,
		Config:    config,
		AccountId: accountId,
	}
	awscm, err := awsclientmgr.Init(awscmConfig)
	assertion.NoError(err, "should not be an error")
	entryMgr := entrymgr.Init()
	exporter, err := Init(ExporterInitConfig{
		AwsClientMgr: awscm,
		EntryMgr:     entryMgr,
		AccountId:    "033197602013",
	})
	assertion.NoError(err, "should not be an error")
	assertion.NotNil(exporter, "should not be nil")
	exporterAssert := exporter.(*_Exporter)
	assertion.NotNil(exporterAssert.entryMgr, "should not be nil")

	// ####################################
	// ADD TO EXPORTER
	// ####################################
	exporter, err = Init(ExporterInitConfig{
		AwsClientMgr: awscm,
		EntryMgr:     entryMgr,
		AccountId:    "033197602013",
	})
	assertion.NoError(err, "should not be an error")
	assertion.NotNil(exporter, "should not be nil")

	// INSUFFICIENT DATA RESULT
	err = exporter.AddEntry(configServiceTypes.Evaluation{
		ComplianceType:       configServiceTypes.ComplianceTypeInsufficientData,
		ComplianceResourceId: aws.String("insufficientDataEvaluationArn"),
		Annotation:           aws.String(""),
		OrderingTimestamp:    aws.Time(time.Now()),
	})
	assertion.NoError(err, "should not be an error")

	// NON COMPLIANT RESULT
	exporter.AddEntry(configServiceTypes.Evaluation{
		ComplianceType:       configServiceTypes.ComplianceTypeNonCompliant,
		ComplianceResourceId: aws.String("nonCompliantEvaulationArn"),
		Annotation:           aws.String("noncompliant"),
		OrderingTimestamp:    aws.Time(time.Now()),
	})
	assertion.NoError(err, "should not be an error")

	// COMPLIANT RESULT
	exporter.AddEntry(configServiceTypes.Evaluation{
		ComplianceType:       configServiceTypes.ComplianceTypeCompliant,
		ComplianceResourceId: aws.String("compliantEvaluationArn"),
		Annotation:           aws.String("compliant"),
		OrderingTimestamp:    aws.Time(time.Now()),
	})
	assertion.NoError(err, "should not be an error")

	err = exporter.WriteToCSV("test.csv")
	assertion.NoError(err, "should not be an error")

	file, err := os.Open("test.csv")
	assertion.NoError(err, "should not be an error")

	key, err := exporter.ExportToS3(string(shared.ConfigFileBucketName), "test.csv", "")
	assertion.NoError(err, "should not be an error")
	assertion.NotEmpty(key, "should not be empty")
	err = exporter.deleteFromS3(string(shared.ConfigFileBucketName), key)
	assertion.NoError(err, "should be an error")

	file.Close()
	err = os.Remove("test.csv")
	assertion.NoError(err, "should not be an error")

	// ####################################
	// ERRORS VALIDATION
	// ####################################

	key, err = exporter.ExportToS3("non-existent-bucket", string(shared.CheckAccessNotGrantedConfigFileObjKey), "")
	assertion.Error(err, "should be an error")
	assertion.Empty(key, "should be empty")
	err = exporter.deleteFromS3("non-existent-bucket", key)
	assertion.Error(err, "should be an error")

}
