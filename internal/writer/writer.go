package writer

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outofoffice3/policy-general/internal/awsclientmgr"
)

// LambdaWriter defines the interface for writing operations in AWS Lambda.
type Writer interface {
	// Write data to s3 bucket
	ExportToS3(bucket, key, prefix string, data []byte) error
	// Write csv file to /tmp directory
	WriteCSV(filename string, header []string, records [][]string) (string, error)
	// Deletes file
	DeleteTempFile(filename string) error
	// Deletes object from S3
	DeleteObjectFromS3(bucket, key, prefix string) error
}

// LambdaTempFileWriter implements LambdaWriter for writing to temporary storage and external services
type _Writer struct {
	awsClientMgr awsclientmgr.AWSClientMgr
	accountId    string
}

type WriterInitConfig struct {
	AWSClientMgr awsclientmgr.AWSClientMgr
	AccountId    string
}

func Init(config WriterInitConfig) (Writer, error) {
	// create new lambda writer
	w, err := newLambdaWriter(config)
	// return errors
	if err != nil {
		return nil, err
	}
	return w, nil
}

// DeleteTempFile deletes a file from the Lambda's /tmp directory.
func (w *_Writer) DeleteTempFile(filename string) error {
	fullPath := filepath.Join("/tmp", filename)
	return os.Remove(fullPath)
}

// DeleteObjectFromS3 deletes a file from an S3 bucket.
func (w *_Writer) DeleteObjectFromS3(bucket, key, prefix string) error {
	client, ok := w.awsClientMgr.GetSDKClient(w.accountId, awsclientmgr.S3)
	if !ok {
		return errors.New("failed to get S3 client")
	}

	s3Client := client.(*s3.Client)

	// Create the full S3 key with the provided prefix
	fullKey := filepath.Join(prefix, key)

	// Delete the file from S3
	_, err := s3Client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(fullKey),
	})

	return err
}

// NewLambdaTempFileWriter creates a new LambdaTempFileWriter.
func newLambdaWriter(config WriterInitConfig) (*_Writer, error) {
	// check if aws client mgr is nil
	if config.AWSClientMgr == nil || config.AccountId == "" {
		return nil, errors.New("aws client mgmr or accountId is not set")
	}
	return &_Writer{
		awsClientMgr: config.AWSClientMgr,
	}, nil
}

// WriteCSVFile writes CSV records to a file in the Lambda's /tmp directory.
func (w *_Writer) WriteCSV(filename string, header []string, records [][]string) (string, error) {
	// Define the full path
	fullPath := filepath.Join("/tmp", filename)

	// Create and open the file
	file, err := os.Create(fullPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Create a CSV writer
	writer := csv.NewWriter(file)

	// Write the header
	if err := writer.Write(header); err != nil {
		return "", err
	}

	// Write the records
	for _, record := range records {
		if err := writer.Write(record); err != nil {
			return "", err
		}
	}
	writer.Flush()

	// Check for errors from the CSV writer
	if err := writer.Error(); err != nil {
		return "", err
	}

	return fullPath, nil
}

// ExportToS3 uploads data to an S3 bucket.
func (w *_Writer) ExportToS3(bucket, key, prefix string, data []byte) error {
	client, ok := w.awsClientMgr.GetSDKClient(w.accountId, awsclientmgr.S3)
	if !ok {
		return errors.New("failed to get S3 client")
	}

	s3Client := client.(*s3.Client)

	// Create the full S3 key with the provided prefix
	fullKey := filepath.Join(prefix, key)

	// Upload the data to S3
	_, err := s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(fullKey),
		Body:   bytes.NewReader(data),
	})

	return err
}
