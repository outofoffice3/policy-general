package errormgr

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outofoffice3/policy-general/internal/awsclientmgr"
	"github.com/outofoffice3/policy-general/internal/shared"
	"github.com/stretchr/testify/assert"
)

func TestStoreErrorPrivate(t *testing.T) {
	assertion := assert.New(t)
	em := New(NewErrorMgrInput{})
	err := Error{
		AccountId:          "1234567890",
		ResourceType:       "testResource",
		PolicyDocumentName: "testPolicy",
		Message:            "test error",
		ResourceArn:        "arn:aws:test::1234567890:testResource",
	}

	em.StoreError(err)

	// Test if the error is stored correctly
	emImpl := em.(*_ErrorMgr)
	assertion.Equal(1, len(emImpl.errors))
	assertion.Equal(err, emImpl.errors[0])
}

func TestWriteToCSVPrivate(t *testing.T) {
	assertion := assert.New(t)
	em := New(NewErrorMgrInput{})
	err := Error{
		AccountId:          "1234567890",
		ResourceType:       "testResource",
		PolicyDocumentName: "testPolicy",
		Message:            "test error",
		ResourceArn:        "arn:aws:test::1234567890:testResource",
	}

	em.StoreError(err)

	filename := "test.csv"
	defer os.Remove(filename) // Clean up file after test

	assertion.NoError(em.WriteToCSV(filename))

	// Verify file contents
	data, fileError := os.ReadFile(filename)
	assertion.NoError(fileError)
	assertion.True(strings.Contains(string(data), "test error"))

	em.StoreError(Error{Message: "test error"})

	invalidFilename := "/invalid/path/test.csv"
	errCSV := em.WriteToCSV(invalidFilename)
	assertion.Error(errCSV)
}

func TestExportToS3Private(t *testing.T) {
	assertion := assert.New(t)
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithSharedConfigProfile("logadmin"))
	assertion.NoError(err)
	config := shared.Config{
		AWSAccounts: []shared.AWSAccount{
			{
				AccountID: "PLACEHOLDER",
				RoleName:  "PLACEHOLDER",
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
	accountId := "PLACEHOLDER"
	awscm, err := awsclientmgr.Init(awsclientmgr.AWSClientMgrInitConfig{
		Ctx:       context.Background(),
		Config:    config,
		Cfg:       cfg,
		AccountId: accountId,
	})
	assertion.NoError(err)
	em := New(NewErrorMgrInput{
		AwsClientMgr: awscm,
		AccountId:    accountId,
	})

	filename := string(shared.ErrorLogFileObjectKey)
	bucket := string(shared.ConfigFileBucketName) // Specify your test bucket
	prefix := "testprefix/"
	defer os.Remove(filename) // Clean up file after test

	// Create a test file
	file, _ := os.Create(filename)
	file.Close()

	// Test exporting to S3
	key, err := em.ExportToS3(bucket, filename, prefix)
	assertion.NoError(err)
	assertion.Equal(prefix+filename, key)

	s3Client := s3.NewFromConfig(cfg)
	_, err = s3Client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	assertion.NoError(err)

	invalidBucket := "nonexistent-bucket"
	key, err = em.ExportToS3(invalidBucket, filename, prefix)
	assertion.Error(err)
	assertion.Empty(key)

}

func TestErrorMessagePrivate(t *testing.T) {
	assertion := assert.New(t)

	// Test with a fully populated error
	fullError := Error{
		AccountId:          "1234567890",
		ResourceType:       "testResource",
		PolicyDocumentName: "testPolicy",
		Message:            "test error message",
		ResourceArn:        "arn:aws:test::1234567890:testResource",
	}
	expectedFullMsg := "AccountId: 1234567890, ResourceType: testResource, PolicyDocumentName: testPolicy, Message: test error message, ResourceArn: arn:aws:test::1234567890:testResource"
	assertion.Equal(expectedFullMsg, fullError.Error())

	// Test with a partially populated error
	partialError := Error{
		AccountId: "1234567890",
		Message:   "partial error message",
	}
	expectedPartialMsg := "AccountId: 1234567890, Message: partial error message"
	assertion.Equal(expectedPartialMsg, partialError.Error())

	// Test with an empty error
	emptyError := Error{}
	expectedEmptyMsg := "unknown error"
	assertion.Equal(expectedEmptyMsg, emptyError.Error())
}
