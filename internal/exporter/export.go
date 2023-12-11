package exporter

import (
	"context"
	"encoding/csv"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outofoffice3/common/logger"
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
}

type _Exporter struct {
	s3Client *s3.Client        // client for S3
	entryMgr entrymgr.EntryMgr // manage execution log entries
	filename string            // filename for execution log
	Logger   logger.Logger     // logger

}

func Init(sos logger.Logger) (Exporter, error) {
	em := entrymgr.Init(sos) // create entry mgr
	e, err := newExporter(NewExporterInput{
		entryMgr: em,
		logger:   sos,
	})
	// return errors
	if err != nil {
		return nil, err
	}
	return e, nil
}

type NewExporterInput struct {
	entryMgr entrymgr.EntryMgr
	logger   logger.Logger
}

// create new exporter
func newExporter(input NewExporterInput) (Exporter, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}

	s3Client := s3.NewFromConfig(cfg)
	e := &_Exporter{
		s3Client: s3Client,
		entryMgr: input.entryMgr,
	}

	if input.logger != nil {
		e.Logger = input.logger
	}
	e.Logger = logger.NewConsoleLogger(logger.LogLevelInfo)

	e.Logger.Infof("exporter successfully created")
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
		e.Logger.Errorf("failed to create file: [%s]", err)
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Writing header
	header := []string{TIMESTAMP, COMPLIANCE, ARN, RESOURCE_TYPE, REASONS, MESSAGE, ERR_MSG, ACCOUNT_ID}
	if err := writer.Write(header); err != nil {
		e.Logger.Errorf("failed to write to file: [%s]", err)
		return err
	}

	// Write insufficient data entries
	insufficientDataEntries, _ := e.entryMgr.GetEntries(string(configServiceTypes.ComplianceTypeInsufficientData))

	for _, entry := range insufficientDataEntries {
		if err := writer.Write([]string{entry.Timestamp, string(entry.Compliance), entry.Arn, entry.ResourceType, entry.Reasons, entry.Message, entry.ErrMsg, entry.AccountId}); err != nil {
			return err
		}
	}
	e.Logger.Infof("Insufficient data entries written to [%s] ", shared.ExecutionLogFileName)

	// write non compliant entries
	nonCompliantEntries, _ := e.entryMgr.GetEntries(string(configServiceTypes.ComplianceTypeNonCompliant))

	for _, entry := range nonCompliantEntries {
		if err := writer.Write([]string{entry.Timestamp, string(entry.Compliance), entry.Arn, entry.ResourceType, entry.Reasons, entry.Message, entry.ErrMsg, entry.AccountId}); err != nil {
			return err
		}
	}
	e.Logger.Infof("Non compliant entries written to [%s] ", shared.ExecutionLogFileName)

	// write compliant entries
	compliantEntries, _ := e.entryMgr.GetEntries(string(configServiceTypes.ComplianceTypeCompliant))

	for _, entry := range compliantEntries {
		if err := writer.Write([]string{entry.Timestamp, string(entry.Compliance), entry.Arn, entry.ResourceType, entry.Reasons, entry.Message, entry.ErrMsg, entry.AccountId}); err != nil {
			return err
		}
	}
	e.Logger.Infof("Compliant entries written to [%s]", shared.ExecutionLogFileName)

	return nil
}

func (e *_Exporter) ExportToS3(bucket string) (string, error) {
	file, err := os.Open(e.filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	timeNow := time.Now()
	key := path.Join(timeNow.Format(time.RFC3339), string(shared.ExecutionLogFileName))
	_, err = e.s3Client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   file,
	})

	if err != nil {
		e.Logger.Errorf("Error uploading to S3: [%s]", err)
		return "", err
	}

	e.Logger.Infof("File uploaded to %s/%s\n", shared.ConfigFileBucketName, shared.ExecutionLogFileName)
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

func JoinReasons(reasons []accessAnalyzerTypes.ReasonSummary, separator string) string {
	var reasonsStrs []string
	for _, reason := range reasons {
		reasonsStrs = append(reasonsStrs, *reason.Description)
		// You can include other fields from ReasonSummary if needed
	}
	return strings.Join(reasonsStrs, separator)
}
