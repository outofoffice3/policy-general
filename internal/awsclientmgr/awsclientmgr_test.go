package awsclientmgr

import (
	"context"
	"log"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outofoffice3/policy-general/internal/shared"
	"github.com/stretchr/testify/assert"
)

func TestAwsClientMgr(t *testing.T) {
	assertion := assert.New(t)
	cfg, _ := config.LoadDefaultConfig(context.Background())

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

	accountId := "033197602013"
	awscm := Init(AWSClientMgrInitConfig{
		Config:    config,
		AccountId: accountId,
		Cfg:       cfg,
	})
	assertion.NotNil(awscm)

	iamClient, ok := awscm.GetSDKClient(accountId, IAM)
	assertion.True(ok)
	assertion.NotNil(iamClient)
	iamClientAssert, ok := iamClient.(*iam.Client)
	assertion.True(ok)
	assertion.IsType(&iam.Client{}, iamClientAssert)

	// test access
	output, err := iamClientAssert.GetUser(context.Background(), &iam.GetUserInput{})
	assertion.NoError(err)
	assertion.NotNil(output)
	log.Printf("%+v", output)

	aaClient, ok := awscm.GetSDKClient(accountId, AA)
	assertion.True(ok)
	assertion.NotNil(aaClient)
	aaClientAssert, ok := aaClient.(*accessanalyzer.Client)
	assertion.True(ok)
	assertion.IsType(&accessanalyzer.Client{}, aaClientAssert)

	// test access
	aaOutput, err := aaClientAssert.ListAnalyzers(context.Background(), &accessanalyzer.ListAnalyzersInput{})
	assertion.NoError(err)
	assertion.NotNil(aaOutput)
	log.Printf("%+v", aaOutput)

	s3Client, ok := awscm.GetSDKClient(accountId, S3)
	assertion.True(ok)
	assertion.NotNil(s3Client)
	s3ClientAssert, ok := s3Client.(*s3.Client)
	assertion.True(ok)
	assertion.IsType(&s3.Client{}, s3ClientAssert)

	accountIds := awscm.GetAccountIds()
	assertion.Equal(2, len(accountIds))

	err = awscm.SetSDKClient(accountId, AWSServiceName("non-existent"), nil)
	assertion.Error(err)
	sdkClient := &iam.Client{}
	err = awscm.SetSDKClient(accountId, AWSServiceName("non-existent"), sdkClient)
	assertion.Error(err)
	resultClient, ok := awscm.GetSDKClient(accountId, AWSServiceName("non-existent"))
	assertion.False(ok)
	assertion.Nil(resultClient)

}
