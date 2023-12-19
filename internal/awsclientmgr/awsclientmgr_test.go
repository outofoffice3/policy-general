package awsclientmgr

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outofoffice3/policy-general/internal/shared"
	"github.com/stretchr/testify/assert"
)

func TestAwsClientMgr(t *testing.T) {
	assertion := assert.New(t)
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithSharedConfigProfile("PLACEDHOLDER"),
		config.WithRegion("PLACEHOLDER"))
	if err != nil {
		panic("configuration error, " + err.Error())
	}
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
		Scope:    "all",
		TestMode: "true",
	}

	accountId := "PLACEHOLDER"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	awscm, err := Init(AWSClientMgrInitConfig{
		Config:    config,
		AccountId: accountId,
		Cfg:       cfg,
		Ctx:       ctx,
	})
	assertion.NoError(err)
	assertion.NotNil(awscm)

	for _, accountId := range awscm.GetAccountIds() {
		iamClient, ok := awscm.GetSDKClient(accountId, IAM)
		assertion.True(ok)
		assertion.NotNil(iamClient)
		iamClientAssert, ok := iamClient.(*iam.Client)
		assertion.True(ok)
		assertion.IsType(&iam.Client{}, iamClientAssert)

		aaClient, ok := awscm.GetSDKClient(accountId, AA)
		assertion.True(ok)
		assertion.NotNil(aaClient)
		aaClientAssert, ok := aaClient.(*accessanalyzer.Client)
		assertion.True(ok)
		assertion.IsType(&accessanalyzer.Client{}, aaClientAssert)
	}

	s3Client, ok := awscm.GetSDKClient(accountId, S3)
	assertion.True(ok)
	assertion.NotNil(s3Client)
	s3ClientAssert, ok := s3Client.(*s3.Client)
	assertion.True(ok)
	assertion.IsType(&s3.Client{}, s3ClientAssert)

	configClient, ok := awscm.GetSDKClient(accountId, CONFIG)
	assertion.True(ok)
	assertion.NotNil(configClient)
	configClientAssert, ok := configClient.(*configservice.Client)
	assertion.True(ok)
	assertion.IsType(&configservice.Client{}, configClientAssert)

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

	errorConfig := shared.Config{
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
		Scope:    "all",
		TestMode: "true",
	}

	// make invalid credentials to force error cases
	cfg.Credentials = aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, nil
	})
	errorTest, forceErr := Init(AWSClientMgrInitConfig{
		Config:    errorConfig,
		AccountId: "invalid account id",
		Cfg:       cfg,
		Ctx:       ctx,
	})
	assertion.Error(forceErr)
	assertion.Nil(errorTest)
}
