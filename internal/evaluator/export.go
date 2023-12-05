package evaluator

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	accessTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outofoffice3/policy-general/internal/evaluator/evaltypes"
)

type Exporter interface {
	// write to csv
	WriteToCSV(entries []evaltypes.ComplianceEvaluation, fileName string) error
	// export entries to AWS S3 bucket
	ExportToS3(entries []evaltypes.ComplianceEvaluation) error
}

type _Exporter struct {
	s3Client *s3.Client // client for S3
}

func NewExporter() (*_Exporter, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	s3Client := s3.NewFromConfig(cfg)
	return &_Exporter{
		s3Client: s3Client,
	}, nil
}

func (e *_Exporter) WriteToCSV(entries []evaltypes.ComplianceEvaluation) error {
	file, err := os.Create(evaltypes.EXECUTION_LOG_FILE_NAME)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Writing header
	header := []string{"Timestamp", "Compliance", "Arn", "ResourceType", "Reasons", "Message", "ErrMsg", "AccountId"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Writing data
	for _, entry := range entries {
		// flatten reasons array and create execution log entry
		reasons := joinReasons(entry.ComplianceResult.Reasons, ";")
		executionLogEntry := evaltypes.ExecutionLogEntry{
			Timestamp:    entry.Timestamp.Format(time.RFC3339),
			Compliance:   entry.ComplianceResult.Compliance,
			Arn:          entry.Arn,
			ResourceType: entry.ResourceType,
			Reasons:      reasons,
			Message:      entry.ComplianceResult.Message,
			ErrMsg:       entry.ErrMsg,
			AccountId:    entry.AccountId,
		}

		// map entry to row item for csv
		row := []string{
			executionLogEntry.Timestamp,
			string(executionLogEntry.Compliance),
			executionLogEntry.Arn,
			string(executionLogEntry.ResourceType),
			executionLogEntry.Reasons,
			executionLogEntry.Message,
			executionLogEntry.ErrMsg,
			executionLogEntry.AccountId,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func (e *_Exporter) ExportToS3(entries []evaltypes.ComplianceEvaluation) error {
	file, err := os.Open(evaltypes.EXECUTION_LOG_FILE_NAME)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = e.s3Client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(os.Getenv(evaltypes.CONFIG_FILE_BUCKET_NAME)),
		Key:    aws.String(evaltypes.EXECUTION_LOG_FILE_NAME),
		Body:   file,
	})

	if err != nil {
		fmt.Println("Error uploading to S3:", err)
		return err
	}

	fmt.Printf("File uploaded to %s/%s\n", evaltypes.CONFIG_FILE_BUCKET_NAME, evaltypes.EXECUTION_LOG_FILE_NAME)
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
