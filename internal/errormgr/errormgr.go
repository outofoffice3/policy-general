package errormgr

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outofoffice3/policy-general/internal/awsclientmgr"
	"github.com/outofoffice3/policy-general/internal/shared"
)

// Error defines the structure of an error that can be reported.
type Error struct {
	AccountId          string
	ResourceType       string
	PolicyDocumentName string
	Message            string
	ResourceArn        string
}

func (e Error) Error() string {
	var parts []string

	if e.AccountId != "" {
		parts = append(parts, "AccountId: "+e.AccountId)
	}
	if e.ResourceType != "" {
		parts = append(parts, "ResourceType: "+e.ResourceType)
	}
	if e.PolicyDocumentName != "" {
		parts = append(parts, "PolicyDocumentName: "+e.PolicyDocumentName)
	}
	if e.Message != "" {
		parts = append(parts, "Message: "+e.Message)
	}
	if e.ResourceArn != "" {
		parts = append(parts, "ResourceArn: "+e.ResourceArn)
	}

	if len(parts) == 0 {
		return "unknown error"
	}

	return strings.Join(parts, ", ")
}

// ErrorMgr defines the interface for an error reporting service.
type ErrorMgr interface {
	// StoreError stores an error for later reporting in a thread-safe manner.
	StoreError(err Error)

	// WriteToCSV writes the stored errors to a CSV file.
	WriteToCSV(filename string) error

	// export data to s3
	ExportToS3(bucket, filename, prefix string) (string, error)
}

type NewErrorMgrInput struct {
	AwsClientMgr awsclientmgr.AWSClientMgr
	AccountId    string
}

// New returns a new instance of an ErrorMgr.
func New(input NewErrorMgrInput) ErrorMgr {
	return &_ErrorMgr{
		errors:       make([]Error, 0),
		mu:           &sync.Mutex{},
		awsClientMgr: input.AwsClientMgr,
		accountId:    input.AccountId,
	}
}

type _ErrorMgr struct {
	accountId    string
	errors       []Error
	mu           *sync.Mutex
	awsClientMgr awsclientmgr.AWSClientMgr
}

func (e *_ErrorMgr) StoreError(err Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errors = append(e.errors, err)
}

func (e *_ErrorMgr) WriteToCSV(filename string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV header
	writer.Write([]string{"AccountId", "ResourceType", "ResourceArn", "PolicyDocumentName", "Message"})

	for _, err := range e.errors {
		record := []string{err.AccountId, err.ResourceType, err.ResourceArn, err.PolicyDocumentName, err.Message}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("error writing to CSV: %w", err)
		}
	}

	return nil
}

func (e *_ErrorMgr) ExportToS3(bucket, filename, prefix string) (string, error) {
	var client *s3.Client
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	clientResult, _ := e.awsClientMgr.GetSDKClient(e.accountId, awsclientmgr.S3)
	client = clientResult.(*s3.Client)

	key := path.Join(prefix, filename)
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
