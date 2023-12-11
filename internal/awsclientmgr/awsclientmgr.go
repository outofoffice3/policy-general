package awsclientmgr

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/outofoffice3/common/logger"
	"github.com/outofoffice3/policy-general/internal/shared"
)

type AWSClientMgr interface {
	// set aws sdk client
	Set(accountId string, name AWSServiceName, client interface{}) error
	// get aws sdk client
	Get(accountId string, name AWSServiceName) (interface{}, bool)
	// get logger
	GetLogger() logger.Logger
	// set bucket name
	setBucketName(bucketName string)
	// get bucket name
	getBucketName() string
	// set config file key
	setConfigObjKey(configObjKey string)
	// get config file key
	getConfigObjKey() string
	// return client map
	GetAccountIds() []string
}

type _AWSClientMgr struct {
	iamClientMap            map[string]*iam.Client
	accessAnalyzerClientMap map[string]*accessanalyzer.Client
	s3ClientMap             map[string]*s3.Client
	bucketName              string
	configObjKey            string
	logger                  logger.Logger
}

func Init(sos logger.Logger, configfile shared.CheckNoAccessConfig) AWSClientMgr {
	cfg, err := config.LoadDefaultConfig(context.Background())
	// return errors
	if err != nil {
		sos.Errorf("failed to load aws config: %s", err)
		panic("failed to load aws config: " + err.Error())
	}

	if sos == nil {
		sos = logger.NewConsoleLogger(logger.LogLevelInfo)
	}
	sos.Debugf("init aws client")
	awsclient := NewAWSClientMgr(sos)
	accountId := configfile.AccountId

	// load iam, access analyzer, s3 & config clients for current account
	iamClient := iam.NewFromConfig(cfg)
	awsclient.Set(accountId, IAM, iamClient)
	sos.Debugf("iam client loaded")
	aaClient := accessanalyzer.NewFromConfig(cfg)
	awsclient.Set(accountId, AA, aaClient)
	sos.Debugf("access analyzer client loaded")
	s3Client := s3.NewFromConfig(cfg)
	awsclient.Set(accountId, S3, s3Client)
	sos.Debugf("s3 client loaded")
	configClient := configservice.NewFromConfig(cfg)
	awsclient.Set(accountId, CONFIG, configClient)
	sos.Debugf("config client loaded")

	// load client maps with sdk clients
	stsClient := sts.NewFromConfig(cfg)
	for _, awsAccount := range configfile.Config.AWSAccounts {
		creds := stscreds.NewAssumeRoleProvider(stsClient, awsAccount.RoleName)
		cfg.Credentials = aws.NewCredentialsCache(creds)
		iamClient := iam.NewFromConfig(cfg)
		awsclient.Set(awsAccount.AccountID, IAM, iamClient)
		sos.Debugf("iam client added for account id [%s]", accountId)
		aaClient := accessanalyzer.NewFromConfig(cfg)
		awsclient.Set(awsAccount.AccountID, AA, aaClient)
		sos.Debugf("access analyzer client added for account id [%s]", accountId)
	}
	return awsclient
}

func NewAWSClientMgr(sos logger.Logger) AWSClientMgr {
	return &_AWSClientMgr{
		iamClientMap:            make(map[string]*iam.Client),
		accessAnalyzerClientMap: make(map[string]*accessanalyzer.Client),
		s3ClientMap:             make(map[string]*s3.Client),
		logger:                  sos,
	}
}

// set aws sdk client
func (a *_AWSClientMgr) Set(accountId string, serviceName AWSServiceName, client interface{}) error {
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

		}
	}
	return nil
}

// get aws sdk client
func (a *_AWSClientMgr) Get(accountId string, serviceName AWSServiceName) (interface{}, bool) {
	sos := a.GetLogger()
	sos.Debugf("getting [%s] client for account id [%s]", serviceName, accountId)
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
			sos.Debugf("default service name case")
		}
	}
	return nil, false
}

// get logger
func (a *_AWSClientMgr) GetLogger() logger.Logger {
	return a.logger
}

// set bucket name
func (a *_AWSClientMgr) setBucketName(bucketName string) {
	a.bucketName = bucketName
}

// get bucket name
func (a *_AWSClientMgr) getBucketName() string {
	return a.bucketName
}

// set config file key
func (a *_AWSClientMgr) setConfigObjKey(configObjKey string) {
	a.configObjKey = configObjKey
}

// get config file key
func (a *_AWSClientMgr) getConfigObjKey() string {
	return a.configObjKey
}

// get account ids
func (a *_AWSClientMgr) GetAccountIds() []string {
	accountIds := make([]string, 0)
	for accountId := range a.iamClientMap {
		accountIds = append(accountIds, accountId)
	}
	return accountIds
}
