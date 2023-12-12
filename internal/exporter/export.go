package exporter

import (
	"context"
	"encoding/csv"
	"errors"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outofoffice3/policy-general/internal/awsclientmgr"
	"github.com/outofoffice3/policy-general/internal/entrymgr"
	"github.com/outofoffice3/policy-general/internal/shared"
)

type Exporter interface {
	// write to csv
	WriteToCSV(filename string) error
	// export entries to AWS S3 bucket
	ExportToS3(bucket string) (string, error)
	// add entry
	AddEntry(entry shared.ComplianceEvaluation) error
	// delete file from s3
	deleteFromS3(bucket string, key string) error
}

type _Exporter struct {
	awsClientMgr awsclientmgr.AWSClientMgr // manage AWS clients
	entryMgr     entrymgr.EntryMgr         // manage execution log entries
	filename     string                    // filename for execution log
	accountId    string
}

func Init(config ExporterInitConfig) (Exporter, error) {
	em := entrymgr.Init() // create entry mgr
	e, err := newExporter(ExporterInitConfig{
		EntryMgr:     em,
		AwsClientMgr: config.AwsClientMgr,
		AccountId:    config.AccountId,
	})
	// return errors
	if err != nil {
		return nil, err
	}
	return e, nil
}

type ExporterInitConfig struct {
	AwsClientMgr awsclientmgr.AWSClientMgr
	EntryMgr     entrymgr.EntryMgr
	AccountId    string
}

// create new exporter
func newExporter(input ExporterInitConfig) (Exporter, error) {
	if input.AwsClientMgr == nil {
		return nil, errors.New("aws client mgr not set")
	}
	e := &_Exporter{
		awsClientMgr: input.AwsClientMgr,
		entryMgr:     input.EntryMgr,
		accountId:    input.AccountId,
	}

	log.Println("exporter successfully created")
	return e, nil
}

// add entry
func (e *_Exporter) AddEntry(entry shared.ComplianceEvaluation) error {
	executionLogEntry := shared.ExecutionLogEntry{
		Timestamp:    entry.Timestamp.Format(time.RFC3339),
		Compliance:   string(entry.ComplianceResult.Compliance),
		Arn:          entry.Arn,
		ResourceType: string(entry.ResourceType),
		Reasons:      JoinReasons(entry.ComplianceResult.Reasons, ";"),
		Message:      entry.ComplianceResult.Message,
		ErrMsg:       entry.ErrMsg,
		AccountId:    entry.AccountId,
	}

	return e.entryMgr.Add(executionLogEntry)
}

// write entries to csv
func (e *_Exporter) WriteToCSV(filename string) error {
	e.filename = filename
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("failed to create file: [%s]\n", err)
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Writing header
	header := []string{TIMESTAMP, COMPLIANCE, ARN, RESOURCE_TYPE, REASONS, MESSAGE, ERR_MSG, ACCOUNT_ID}
	if err := writer.Write(header); err != nil {
		log.Printf("failed to write to file: [%s]\n", err)
		return err
	}

	// Write insufficient data entries
	insufficientDataEntries, _ := e.entryMgr.GetEntries(string(configServiceTypes.ComplianceTypeInsufficientData))

	for _, entry := range insufficientDataEntries {
		if err := writer.Write([]string{entry.Timestamp, string(entry.Compliance), entry.Arn, entry.ResourceType, entry.Reasons, entry.Message, entry.ErrMsg, entry.AccountId}); err != nil {
			return err
		}
	}
	log.Printf("Insufficient data entries written to [%s]\n", filename)

	// write non compliant entries
	nonCompliantEntries, _ := e.entryMgr.GetEntries(string(configServiceTypes.ComplianceTypeNonCompliant))

	for _, entry := range nonCompliantEntries {
		if err := writer.Write([]string{entry.Timestamp, string(entry.Compliance), entry.Arn, entry.ResourceType, entry.Reasons, entry.Message, entry.ErrMsg, entry.AccountId}); err != nil {
			return err
		}
	}
	log.Printf("Non compliant entries written to [%s]\n", filename)

	// write compliant entries
	compliantEntries, _ := e.entryMgr.GetEntries(string(configServiceTypes.ComplianceTypeCompliant))

	for _, entry := range compliantEntries {
		if err := writer.Write([]string{entry.Timestamp, string(entry.Compliance), entry.Arn, entry.ResourceType, entry.Reasons, entry.Message, entry.ErrMsg, entry.AccountId}); err != nil {
			return err
		}
	}
	log.Printf("Compliant entries written to [%s]\n", filename)

	return nil
}

func (e *_Exporter) ExportToS3(bucket string) (string, error) {
	var client *s3.Client
	file, err := os.Open(e.filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	clientResult, _ := e.awsClientMgr.GetSDKClient(e.accountId, awsclientmgr.S3)
	client = clientResult.(*s3.Client)
	timeNow := time.Now()

	key := path.Join(timeNow.Format(time.RFC3339), string(shared.ExecutionLogFileName))
	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   file,
	})

	if err != nil {
		log.Printf("Error uploading to S3: [%s]\n", err)
		return "", err
	}

	log.Printf("File uploaded to %s/%s\n", shared.ConfigFileBucketName, shared.ExecutionLogFileName)
	return key, nil
}

func CreateAWSConfigEvaluation(evaluation shared.ComplianceEvaluation) configServiceTypes.Evaluation {
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

// delete file from s3
func (e *_Exporter) deleteFromS3(bucket string, key string) error {
	var client *s3.Client
	clientResult, _ := e.awsClientMgr.GetSDKClient(e.accountId, awsclientmgr.S3)
	client = clientResult.(*s3.Client)

	_, err := client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		log.Printf("Error deleting file from S3: [%s]\n", err)
		return err
	}
	log.Printf("File deleted from %s/%s\n", shared.ConfigFileBucketName, shared.ExecutionLogFileName)
	return nil
}

func JoinReasons(reasons []accessAnalyzerTypes.ReasonSummary, separator string) string {
	var reasonsStrs []string
	for _, reason := range reasons {
		reasonsStrs = append(reasonsStrs, *reason.Description)
		// You can include other fields from ReasonSummary if needed
	}
	return strings.Join(reasonsStrs, separator)
}
