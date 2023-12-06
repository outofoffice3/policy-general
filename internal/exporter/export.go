package exporter

import (
	"context"
	"encoding/csv"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	accessTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
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
	ExportToS3(bucket string) error
	// add entry
	Add(entry shared.ComplianceEvaluation) error
	// get logger
	GetLogger() logger.Logger
}

type _Exporter struct {
	s3Client *s3.Client        // client for S3
	entryMgr entrymgr.EntryMgr // manage execution log entries
	filename string            // filename for execution log
	logger   logger.Logger     // logger

}

// create new exporter
func NewExporter(sos logger.Logger) (Exporter, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	s3Client := s3.NewFromConfig(cfg)
	return &_Exporter{
		s3Client: s3Client,
		logger:   sos,
	}, nil
}

// add entry
func (e *_Exporter) Add(entry shared.ComplianceEvaluation) error {
	return e.entryMgr.Add(shared.ExecutionLogEntry{
		Timestamp:    entry.Timestamp.Format(time.RFC3339),
		Compliance:   string(entry.ComplianceResult.Compliance),
		Arn:          entry.Arn,
		ResourceType: string(entry.ResourceType),
		Reasons:      joinReasons(entry.ComplianceResult.Reasons, ";"),
		Message:      entry.ComplianceResult.Message,
		ErrMsg:       entry.ErrMsg,
		AccountId:    entry.AccountId,
	})
}

// write entries to csv
func (e *_Exporter) WriteToCSV(filename string) error {
	sos := e.GetLogger()
	e.filename = filename
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Writing header
	header := []string{TIMESTAMP, COMPLIANCE, ARN, RESOURCE_TYPE, REASONS, MESSAGE, ERR_MSG, ACCOUNT_ID}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write insufficient data entries
	insufficientDataEntries, err := e.entryMgr.GetEntries(string(configServiceTypes.ComplianceTypeInsufficientData))
	if err != nil {
		return err
	}
	for _, entry := range insufficientDataEntries {
		if err := writer.Write([]string{entry.Timestamp, string(entry.Compliance), entry.Arn, entry.ResourceType, entry.Reasons, entry.Message, entry.ErrMsg, entry.AccountId}); err != nil {
			return err
		}
	}
	sos.Infof("Insufficient data entries written to", shared.EXECUTION_LOG_FILE_NAME)

	// write non compliant entries
	nonCompliantEntries, err := e.entryMgr.GetEntries(string(configServiceTypes.ComplianceTypeNonCompliant))
	if err != nil {
		return err
	}
	for _, entry := range nonCompliantEntries {
		if err := writer.Write([]string{entry.Timestamp, string(entry.Compliance), entry.Arn, entry.ResourceType, entry.Reasons, entry.Message, entry.ErrMsg, entry.AccountId}); err != nil {
			return err
		}
	}
	sos.Infof("Non compliant entries written to", shared.EXECUTION_LOG_FILE_NAME)

	// write compliant entries
	compliantEntries, err := e.entryMgr.GetEntries(string(configServiceTypes.ComplianceTypeCompliant))
	if err != nil {
		return err
	}
	for _, entry := range compliantEntries {
		if err := writer.Write([]string{entry.Timestamp, string(entry.Compliance), entry.Arn, entry.ResourceType, entry.Reasons, entry.Message, entry.ErrMsg, entry.AccountId}); err != nil {
			return err
		}
	}
	sos.Infof("Compliant entries written to", shared.EXECUTION_LOG_FILE_NAME)

	return nil
}

func (e *_Exporter) ExportToS3(bucket string) error {
	sos := e.GetLogger()
	file, err := os.Open(e.filename)
	if err != nil {
		return err
	}
	defer file.Close()

	timeNow := time.Now()
	_, err = e.s3Client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(timeNow.Format(time.RFC3339) + "/" + shared.EXECUTION_LOG_FILE_NAME + ".csv"),
		Body:   file,
	})

	if err != nil {
		sos.Errorf("Error uploading to S3:", err)
		return err
	}

	sos.Infof("File uploaded to %s/%s\n", shared.CONFIG_FILE_BUCKET_NAME, shared.EXECUTION_LOG_FILE_NAME)
	return nil
}

func joinReasons(reasons []accessTypes.ReasonSummary, separator string) string {
	var reasonsStrs []string
	for _, reason := range reasons {
		reasonsStrs = append(reasonsStrs, *reason.Description)
		// You can include other fields from ReasonSummary if needed
	}
	return strings.Join(reasonsStrs, separator)
}

// get logger
func (e *_Exporter) GetLogger() logger.Logger {
	return e.logger
}
