package exporter

import (
	"context"
	"encoding/csv"
	"errors"
	"log"
	"os"
	"path"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
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
	ExportToS3(bucket string, filename string, prefix string) (string, error)
	// add entry
	AddEntry(entry configServiceTypes.Evaluation) error
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
func (e *_Exporter) AddEntry(entry configServiceTypes.Evaluation) error {
	return e.entryMgr.AddEntry(entry)
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
	if err := writer.Write([]string{ComplianceResourceId, ComplianceType, Annotation, OrderingTimestamp}); err != nil {
		log.Printf("failed to write to file: [%s]\n", err)
		return err
	}

	// Write insufficient data entries
	insufficientDataEntries, _ := e.entryMgr.GetEntries(string(configServiceTypes.ComplianceTypeInsufficientData))

	for _, entry := range insufficientDataEntries {
		if err := writer.Write([]string{*entry.ComplianceResourceId, string(entry.ComplianceType), *entry.Annotation, entry.OrderingTimestamp.Format(time.RFC3339)}); err != nil {
			return err
		}
	}
	log.Printf("Insufficient data entries written to [%s]\n", filename)

	// write not applicable entries
	notApplicableEntries, _ := e.entryMgr.GetEntries(string(configServiceTypes.ComplianceTypeNotApplicable))

	for _, entry := range notApplicableEntries {
		if err := writer.Write([]string{*entry.ComplianceResourceId, string(entry.ComplianceType), *entry.Annotation, entry.OrderingTimestamp.Format(time.RFC3339)}); err != nil {
			return err
		}
	}
	log.Printf("Not applicable entries written to [%s]\n", filename)

	// write non compliant entries
	nonCompliantEntries, _ := e.entryMgr.GetEntries(string(configServiceTypes.ComplianceTypeNonCompliant))

	for _, entry := range nonCompliantEntries {
		if err := writer.Write([]string{*entry.ComplianceResourceId, string(entry.ComplianceType), *entry.Annotation, entry.OrderingTimestamp.Format(time.RFC3339)}); err != nil {
			return err
		}
	}
	log.Printf("Non compliant entries written to [%s]\n", filename)

	// write compliant entries
	compliantEntries, _ := e.entryMgr.GetEntries(string(configServiceTypes.ComplianceTypeCompliant))

	for _, entry := range compliantEntries {
		if err := writer.Write([]string{*entry.ComplianceResourceId, string(entry.ComplianceType), *entry.Annotation, entry.OrderingTimestamp.Format(time.RFC3339)}); err != nil {
			return err
		}
	}
	log.Printf("Compliant entries written to [%s]\n", filename)

	return nil
}

func (e *_Exporter) ExportToS3(bucket, filename, prefix string) (string, error) {
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
