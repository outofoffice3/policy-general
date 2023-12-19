package awsclientmgr

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"

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
	ctx                     context.Context
	iamClientMap            map[string]*iam.Client
	accessAnalyzerClientMap map[string]*accessanalyzer.Client
	s3ClientMap             map[string]*s3.Client
	configClientMap         map[string]*configservice.Client
}

type AWSClientMgrInitConfig struct {
	Ctx       context.Context
	Cfg       aws.Config
	Config    shared.Config
	AccountId string
}

func Init(pkgConfig AWSClientMgrInitConfig) (AWSClientMgr, error) {
	cfg := pkgConfig.Cfg
	log.Printf("init aws client")
	awsclient := NewAWSClientMgr(pkgConfig.Ctx)
	accountId := pkgConfig.AccountId
	sdkConfig := cfg.Copy()

	// create channel for collecting errors from go routines
	errorChan := make(chan error, 1)

	initWg := &sync.WaitGroup{}
	initWg.Add(1)
	go func() {
		defer initWg.Done()
		// load iam, access analyzer, s3 & config clients for current account
		iamClient := iam.NewFromConfig(sdkConfig)
		_, err := iamClient.ListRoles(pkgConfig.Ctx, &iam.ListRolesInput{})
		if err != nil {
			log.Printf("error loading iam client: %v", err)
			errorChan <- errors.New("error loading iam client : [" + err.Error() + "]")
		}
		awsclient.SetSDKClient(accountId, IAM, iamClient)
		log.Printf("iam client loaded for account id [%v]\n", accountId)

		aaClient := accessanalyzer.NewFromConfig(sdkConfig)
		_, err = aaClient.ListAnalyzers(pkgConfig.Ctx, &accessanalyzer.ListAnalyzersInput{})
		if err != nil {
			log.Printf("error loading access analyzer client: %v", err)
			errorChan <- errors.New("error loading access analyzer client : [" + err.Error() + "]")
		}
		awsclient.SetSDKClient(accountId, AA, aaClient)
		log.Printf("access analyzer client loaded for account id [%v]\n", accountId)

		s3Client := s3.NewFromConfig(sdkConfig)
		_, err = s3Client.ListBuckets(pkgConfig.Ctx, &s3.ListBucketsInput{})
		if err != nil {
			log.Printf("error loading s3 client: %v", err)
			errorChan <- errors.New("error loading s3 client : [" + err.Error() + "]")
		}
		awsclient.SetSDKClient(accountId, S3, s3Client)
		log.Printf("s3 client loaded for account id [%v]\n", accountId)

		configClient := configservice.NewFromConfig(sdkConfig)
		_, err = configClient.DescribeConfigurationRecorders(pkgConfig.Ctx, &configservice.DescribeConfigurationRecordersInput{})
		if err != nil {
			log.Printf("error loading config client: %v", err)
			errorChan <- errors.New("error loading config client : [" + err.Error() + "]")
		}
		awsclient.SetSDKClient(accountId, CONFIG, configClient)
		log.Printf("config client loaded with account id [%v]\n", accountId)
	}()

	// load client maps with sdk clients
	stsClient := sts.NewFromConfig(sdkConfig)
	for _, awsAccount := range pkgConfig.Config.AWSAccounts {
		initWg.Add(1)
		go func(account shared.AWSAccount) {
			defer initWg.Done()
			log.Printf("creating sdk client for account id [%v]\n", account)
			creds := stscreds.NewAssumeRoleProvider(stsClient, account.RoleName)
			log.Printf("assuming role [%s]", account.RoleName)

			cfgCopy := cfg.Copy()
			cfgCopy.Credentials = aws.NewCredentialsCache(creds)
			iamClient := iam.NewFromConfig(cfgCopy)
			_, err := iamClient.ListRoles(pkgConfig.Ctx, &iam.ListRolesInput{})
			if err != nil {
				log.Printf("error assuming role [%s]: %v", account.RoleName, err)
				errorChan <- errors.New("error assuming role : [" + err.Error() + "]")
			}

			awsclient.SetSDKClient(account.AccountID, IAM, iamClient)
			log.Printf("iam client added for account id [%s]", account.AccountID)

			aaClient := accessanalyzer.NewFromConfig(cfgCopy)
			_, err = aaClient.ListAnalyzers(pkgConfig.Ctx, &accessanalyzer.ListAnalyzersInput{})
			if err != nil {
				log.Printf("error assuming role [%s]: %v", account.RoleName, err)
				errorChan <- errors.New("error assuming role : [" + err.Error() + "]")
			}
			awsclient.SetSDKClient(account.AccountID, AA, aaClient)
			log.Printf("access analyzer client added for account id [%s]", account.AccountID)
		}(awsAccount)
	}

	// close error channel when init is complete
	go func() {
		initWg.Wait()
		close(errorChan)
	}()

	errMsgs := []string{}
	for err := range errorChan {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) > 0 {
		return nil, errors.New("error loading sdk clients: " + strings.Join(errMsgs, " | "))
	}

	log.Printf("sdk clients loaded successfully for all accounts")
	return awsclient, nil
}

func NewAWSClientMgr(ctx context.Context) AWSClientMgr {
	return &_AWSClientMgr{
		ctx:                     ctx,
		iamClientMap:            make(map[string]*iam.Client),
		accessAnalyzerClientMap: make(map[string]*accessanalyzer.Client),
		s3ClientMap:             make(map[string]*s3.Client),
		configClientMap:         make(map[string]*configservice.Client),
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
	case CONFIG: // CONFIG - AWS Config
		{
			clientAssert := client.(*configservice.Client)
			a.configClientMap[accountId] = clientAssert
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
	case CONFIG:
		{
			client, ok := a.configClientMap[accountId]
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
