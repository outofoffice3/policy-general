package awsclientmgr

import (
	"errors"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/outofoffice3/policy-general/internal/shared"
)

type AWSClientMgr interface {
	// set aws sdk client
	SetSDKClient(accountId string, name AWSServiceName, client interface{}) error
	// get aws sdk client
	GetSDKClient(accountId string, name AWSServiceName) (interface{}, bool)
	// return client map
	GetAccountIds() []string
}

type _AWSClientMgr struct {
	iamClientMap            map[string]*iam.Client
	accessAnalyzerClientMap map[string]*accessanalyzer.Client
	s3ClientMap             map[string]*s3.Client
}

type AWSClientMgrInitConfig struct {
	Cfg       aws.Config
	Config    shared.Config
	AccountId string
}

func Init(pkgConfig AWSClientMgrInitConfig) AWSClientMgr {
	cfg := pkgConfig.Cfg
	log.Printf("init aws client")
	awsclient := NewAWSClientMgr()
	accountId := pkgConfig.AccountId

	// load iam, access analyzer, s3 & config clients for current account
	sdkConfig := cfg.Copy()
	iamClient := iam.NewFromConfig(sdkConfig)
	awsclient.SetSDKClient(accountId, IAM, iamClient)
	log.Printf("iam client loaded for account id [%v]", accountId)

	aaClient := accessanalyzer.NewFromConfig(sdkConfig)
	awsclient.SetSDKClient(accountId, AA, aaClient)
	log.Printf("access analyzer client loaded for account id [%v]", accountId)

	s3Client := s3.NewFromConfig(sdkConfig)
	awsclient.SetSDKClient(accountId, S3, s3Client)
	log.Printf("s3 client loaded for account id [%v]", accountId)

	configClient := configservice.NewFromConfig(sdkConfig)
	awsclient.SetSDKClient(accountId, CONFIG, configClient)
	log.Printf("config client loaded with account id [%v]", accountId)

	// load client maps with sdk clients
	stsClient := sts.NewFromConfig(sdkConfig)
	for _, awsAccount := range pkgConfig.Config.AWSAccounts {
		creds := stscreds.NewAssumeRoleProvider(stsClient, awsAccount.RoleName)
		log.Printf("assuming role [%s]", awsAccount.RoleName)

		sdkConfig.Credentials = aws.NewCredentialsCache(creds)
		iamClient := iam.NewFromConfig(sdkConfig)
		awsclient.SetSDKClient(awsAccount.AccountID, IAM, iamClient)
		log.Printf("iam client added for account id [%s]", awsAccount.AccountID)

		sdkConfig.Credentials = aws.NewCredentialsCache(creds)
		aaClient := accessanalyzer.NewFromConfig(sdkConfig)
		awsclient.SetSDKClient(awsAccount.AccountID, AA, aaClient)
		log.Printf("access analyzer client added for account id [%s]", awsAccount.AccountID)
	}
	return awsclient
}

func NewAWSClientMgr() AWSClientMgr {
	return &_AWSClientMgr{
		iamClientMap:            make(map[string]*iam.Client),
		accessAnalyzerClientMap: make(map[string]*accessanalyzer.Client),
		s3ClientMap:             make(map[string]*s3.Client),
	}
}

// set aws sdk client
func (a *_AWSClientMgr) SetSDKClient(accountId string, serviceName AWSServiceName, client interface{}) error {
	log.Printf("setting [%s] client for account id [%s]", serviceName, accountId)
	if client == nil {
		return errors.New("client is nil")
	}
	switch serviceName {
	case IAM: // IAM - Identity and Access Management

		{
			clientAssert := client.(*iam.Client)
			a.iamClientMap[accountId] = clientAssert
		}
	case AA: // AccessAnalyzer - Access Analyzer

		{
			clientAssert := client.(*accessanalyzer.Client)
			a.accessAnalyzerClientMap[accountId] = clientAssert
		}
	case S3: // S3 - Simple Storage Service
		{
			clientAssert := client.(*s3.Client)
			a.s3ClientMap[accountId] = clientAssert
		}

	default:
		{
			return errors.New("invalid service name")
		}
	}
	return nil
}

// get aws sdk client
func (a *_AWSClientMgr) GetSDKClient(accountId string, serviceName AWSServiceName) (interface{}, bool) {
	log.Printf("getting [%s] client for account id [%s]", serviceName, accountId)
	switch serviceName {
	case IAM: // IAM - Identity and Access Management
		{
			client, ok := a.iamClientMap[accountId]
			return client, ok
		}
	case AA: // AccessAnalyzer - Access Analyzer
		{
			client, ok := a.accessAnalyzerClientMap[accountId]
			return client, ok
		}
	case S3: // S3 - Simple Storage Service
		{
			client, ok := a.s3ClientMap[accountId]
			return client, ok
		}
	default:
		{
			log.Printf("default service name case")
		}
	}
	return nil, false
}

// get account ids
func (a *_AWSClientMgr) GetAccountIds() []string {
	accountIds := make([]string, 0)
	for accountId := range a.iamClientMap {
		accountIds = append(accountIds, accountId)
	}
	return accountIds
}