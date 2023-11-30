package evaluator

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/outofoffice3/common/logger"
	"github.com/outofoffice3/policy-general/pkg/evaluator/evalevents"
	"github.com/outofoffice3/policy-general/pkg/evaluator/evaltypes"
)

/*

Evaluator interface is responsible for the following :

- Handling serialized config event from cloudwatch
- Validating that the actions from the configuration file are valid
- Retrieving IAM clients to use for cross account access
- Checking compliance of a policy document
- Sending evaluation response to AWS Config

*/

type Evaluator interface {
	// entry point for evaluator interface.  Handles serialized config event from cloudwatch
	HandleConfigEvent(event evalevents.ConfigEvent) error

	// ###############################################################################################################
	// PROCESSING COMPLIANCE CHECKING METHODS
	// ###############################################################################################################

	// check identity policies compliance for all iam roles in given aws account
	ProcessComplianceForRoles(accountId string, resultsBuffer chan<- evaltypes.ComplianceEvaluation)
	// check identity policies compliance for all iam users in a given aws account
	ProcessComplianceForUsers(accountId string, resultsBuffer chan<- evaltypes.ComplianceEvaluation)
	// check identity policies compliance for both iam users and iam roles in a given aws account
	ProcessComplianceForAll(accountId string, resultsBuffer chan<- evaltypes.ComplianceEvaluation)

	// ###############################################################################################################
	// DATA VALIDATION METHODS
	// ###############################################################################################################

	// validate restricted actions from configuration file
	IsValidAction(action string) bool
	// validate scope value
	IsValidScope(scope string) bool
	// evaulate if a policy document is compliant
	IsCompliant(client *accessanalyzer.Client, policyDocument string, restrictedActions []string) (evaltypes.ComplianceResult, error)
	// send evaluation response to AWS config
	SendEvaluations(evaluations []configServiceTypes.Evaluation)

	// ###############################################################################################################
	// GETTER & SETTER METHODS
	// ###############################################################################################################

	// sets scope based on config file
	SetScope(scope string)
	// get scope
	GetScope() string
	// get result token
	GetResultToken() string
	// set result token
	SetResultToken(token string)
	// return logger
	GetLogger() logger.Logger
	// return AWS Config Client
	GetAwsConfigClient() *configservice.Client
	// set AWS Config Client
	SetAwsConfigClient(client *configservice.Client)
	// return AWS IAM Client
	GetAwsIamClient(accountId string) *iam.Client
	// set AWS IAM Client
	SetAwsIamClient(accountId string, client *iam.Client)
	// return AWS Access Analyzer Client
	GetAwsAccessAnalyzerClient(accountId string) *accessanalyzer.Client
	// set AWS Access Analyzer Client
	SetAwsAccessAnalyzerClient(accountId string, client *accessanalyzer.Client)
	// return restricted actions
	GetRestrictedActions() []string
	// append restricted actions
	AppendRestrictedAction(action string)
}

type _Evaluator struct {
	wg                      *sync.WaitGroup                   // wait group for go routines
	scope                   string                            // scope of policies you want to cover.  roles , users or all
	resultToken             string                            // token for config evaluation result
	configClient            *configservice.Client             // client for AWS Config
	iamClientMap            map[string]*iam.Client            // iam client map for cross account access
	accessAnalyzerClientMap map[string]*accessanalyzer.Client // access analyer client map for cross account access
	Logger                  logger.Logger                     // logger for evalautor
	restrictedActions       []string                          // restricted actions
}

// ###############################################################################################################
// INTERFACE INITIALIZATION
// ###############################################################################################################

// initialize evaluator
func Init(log logger.Logger) Evaluator {
	/*
			To initialize, evaluator expects a config file in the following format :
			{
		  "awsAccounts": [
		    {
		      "accountId": "your_account_id_1",
		      "roleName": "YourServiceRoleName1"
		    },
		    {
		      "accountId": "your_account_id_2",
		      "roleName": "YourServiceRoleName2"
		    }
		  ],
		  "actions": [
		    "s3:GetObject",
		    "s3:PutObject",
		    "ec2:DescribeInstances",
		    "lambda:InvokeFunction"
		  ],
		  "scope": "all" // valid values = roles, user or all
		}

		The config file will be stored in S3 and the object key will be loaded in the environment
		variable CONFIG_FILE_KEY.  Read the file from s3 and serialze into the evaltypes.Config type.

		type Config struct {
			AwsAccounts []AwsAccount `json:"awsAccounts"`
			Actions     []string     `json:"actions"`
			Scope       string       `json:"scope"`
		}

		Load the client map with *iam.Clients that all have assumed the respective role from the Config.
		They [key] = accound id and [value] = *iam.Client.  Set the scope based on the config file.
		Validate each action from the config file.
	*/
	var (
		defaultLogger       logger.Logger
		complianceEvaluator Evaluator
	)
	// initialize default logger if logger is nil
	if log == nil {
		defaultLogger = logger.NewConsoleLogger(logger.LogLevelInfo)
		complianceEvaluator = newEvaluator(defaultLogger)
	} else {
		complianceEvaluator = newEvaluator(log)

	}
	sos := complianceEvaluator.GetLogger()
	sos.Infof("evaluator init started")

	// read env vars for config file location
	evaluatorConfigBucketName := os.Getenv("CONFIG_FILE_BUCKET_NAME")
	evaluatorConfigObjectKey := os.Getenv("CONFIG_FILE_KEY")
	cfg, err := config.LoadDefaultConfig(context.Background())
	// return errors
	if err != nil {
		initErr := InitError{
			Message: err.Error(),
		}
		HandleError(initErr)
	}

	// retrieve config file from s3
	s3Client := s3.NewFromConfig(cfg)
	getObjectOutput, err := s3Client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(evaluatorConfigBucketName),
		Key:    aws.String(evaluatorConfigObjectKey),
	})
	// return errors
	if err != nil {
		initErr := InitError{
			Message: err.Error(),
		}
		HandleError(initErr)
	}

	// read file contents and serialize to evaltypes.Config struct
	var policyGeneralConfig evaltypes.Config
	objectContent, err := io.ReadAll(getObjectOutput.Body)
	// return errors
	if err != nil {
		initErr := InitError{
			Message: err.Error(),
		}
		HandleError(initErr)
	}
	err = json.Unmarshal(objectContent, &policyGeneralConfig)
	// return errors
	if err != nil {
		initErr := InitError{
			Message: err.Error(),
		}
		HandleError(initErr)
	}

	// validate scope from config file
	if !complianceEvaluator.IsValidScope(policyGeneralConfig.Scope) {
		sos.Errorf("invalid scope [%v] in config file", policyGeneralConfig.Scope)
		HandleError(InitError{
			Message: "invalid scope value in config file",
		})
	}
	complianceEvaluator.SetScope(policyGeneralConfig.Scope)

	// initialize aws config and set to evaluator interface
	configClient := configservice.NewFromConfig(cfg)
	complianceEvaluator.SetAwsConfigClient(configClient)

	// get assume role provider, assume the respective role and load client map
	stsClient := sts.NewFromConfig(cfg)
	for _, awsAccount := range policyGeneralConfig.AWSAccounts {
		creds := stscreds.NewAssumeRoleProvider(stsClient, awsAccount.RoleName)
		cfg.Credentials = aws.NewCredentialsCache(creds)
		iamClient := iam.NewFromConfig(cfg)
		complianceEvaluator.SetAwsIamClient(awsAccount.AccountID, iamClient)
		sos.Debugf("iam client [%v] loaded to map with role [%v]", awsAccount.AccountID, awsAccount.RoleName)
		accessAnalzyerClient := accessanalyzer.NewFromConfig(cfg)
		complianceEvaluator.SetAwsAccessAnalyzerClient(awsAccount.AccountID, accessAnalzyerClient)
		sos.Debugf("access analyzer client [%v] loaded to map with role [%v]", awsAccount.AccountID, awsAccount.RoleName)
	}
	sos.Debugf("iam & access analyzer clients successfully loaded to evaluator interface client maps")

	// validate actions from config file
	for _, action := range policyGeneralConfig.RestrictedActions {
		if !complianceEvaluator.IsValidAction(action) {
			sos.Errorf("invalid action [%v] in config file", action)
			HandleError(InitError{
				Message: "invalid restriced action in config file",
			})
		}
		// add action to policy general
		complianceEvaluator.AppendRestrictedAction(action)
		sos.Debugf("action [%v] added to evaluator interface")
	}
	sos.Infof("evaluator package successfully initialized")
	return complianceEvaluator
}

// ###############################################################################################################
// INTERFACE CONSTRUCTOR
// ###############################################################################################################

// create new evaluator
func newEvaluator(logger logger.Logger) *_Evaluator {
	return &_Evaluator{
		wg:                      &sync.WaitGroup{},
		scope:                   "",
		resultToken:             "",
		configClient:            nil,
		iamClientMap:            make(map[string]*iam.Client),
		accessAnalyzerClientMap: make(map[string]*accessanalyzer.Client),
		Logger:                  logger,
		restrictedActions:       nil,
	}
}

// ###############################################################################################################
// INTERFACE ENTRY POINT
// ###############################################################################################################

// handle config event
func (e *_Evaluator) HandleConfigEvent(event evalevents.ConfigEvent) error {
	e.SetResultToken(event.ResultToken)
	resultsBuffer := make(chan evaltypes.ComplianceEvaluation, len(e.iamClientMap)) // buffered channel to send / receive results on
	// loop through accounts in client map and process compliance check in go routine
	for accountId := range e.iamClientMap {
		e.ProcessComplianceCheck(accountId, resultsBuffer) // process check in go routine
		e.Logger.Debugf("processing compliance check for account [%v]", accountId)
	}

	go func(wg *sync.WaitGroup, resultChannel chan evaltypes.ComplianceEvaluation) {
		wg.Wait() // wait for results to be processed
		e.Logger.Debugf("closing results channel")
		close(resultsBuffer)
	}(e.wg, resultsBuffer)

	// read results from results channel
	var batchEvaluations []configServiceTypes.Evaluation
	maxBatchSize := 100
	currentIndex := 0
	for result := range resultsBuffer {
		e.Logger.Debugf("result received : %v", result)
		if result.ErrMsg != "" {
			e.Logger.Errorf("error processing compliance check for account [%v] : %v", result.AccountId, result.ErrMsg)
		}
		evaulation := configServiceTypes.Evaluation{
			ComplianceResourceType: aws.String(string(result.ResourceType)),
			ComplianceResourceId:   aws.String(result.Arn),
			ComplianceType:         result.Compliance,
			Annotation:             aws.String(result.Annotation),
			OrderingTimestamp:      &result.Timestamp,
		}
		batchEvaluations = append(batchEvaluations, evaulation) // append result to results slice
		currentIndex++
		e.Logger.Debugf("result appended to results slice")

		// check if batch is max size, if so, send to aws config and reset
		if currentIndex >= maxBatchSize {
			e.SendEvaluations(batchEvaluations)
			currentIndex = 0
			continue
		}
	}
	// send remaining results to aws config
	e.SendEvaluations(batchEvaluations)
	return nil
}

// ###############################################################################################################
// PROCESSING COMPLIANCE INTERFACE METHODS
// ###############################################################################################################

// process compliance check for an aws account
func (e *_Evaluator) ProcessComplianceCheck(accountId string, resultsBuffer chan<- evaltypes.ComplianceEvaluation) error {
	switch strings.ToLower(e.scope) {
	case "roles":
		e.wg.Add(1)
		go e.ProcessComplianceForRoles(accountId, resultsBuffer)
	case "users":
		e.wg.Add(1)
		go e.ProcessComplianceForUsers(accountId, resultsBuffer)
	case "all":
		e.wg.Add(1)
		go e.ProcessComplianceForAll(accountId, resultsBuffer)
	}
	return nil
}

// process compliance for iam roles
func (e *_Evaluator) ProcessComplianceForRoles(accountId string, resultsBuffer chan<- evaltypes.ComplianceEvaluation) {
	defer e.wg.Done()
	iamClient := e.GetAwsIamClient(accountId)
	accessAnalyzerClient := e.GetAwsAccessAnalyzerClient(accountId)
	// list all policies for roles
	listRolePaginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{})
	for listRolePaginator.HasMorePages() {
		listRolePage, err := listRolePaginator.NextPage(context.Background())
		// check for errors
		if err != nil {
			e.Logger.Errorf("error retrieving list of roles : %v", err)
			complianceEvaluation := evaltypes.ComplianceEvaluation{
				AccountId:    accountId,
				ResourceType: evaltypes.NOT_SPECIFIED,
				Arn:          "",
				Compliance:   configServiceTypes.ComplianceTypeInsufficientData,
				ErrMsg:       err.Error(),
				Timestamp:    time.Now(),
				Annotation:   "",
			}
			processingErr := ProcessingError{
				Wg:                   e.wg,
				ComplianceEvaluation: complianceEvaluation,
				Result:               resultsBuffer,
				Message:              err.Error(),
			}
			HandleError(processingErr)
			return
		}
		for _, role := range listRolePage.Roles {
			e.Logger.Debugf("processing compliance check for role [%v]", *role.RoleName)
			// loop through all policies attached to role and retrieve policy document
			listRolePolicyPaginator := iam.NewListRolePoliciesPaginator(iamClient, &iam.ListRolePoliciesInput{
				RoleName: role.RoleName,
			})
			for listRolePolicyPaginator.HasMorePages() {
				listRolePoliciesPage, err := listRolePolicyPaginator.NextPage(context.Background())
				// check for errors
				if err != nil {
					e.Logger.Errorf("error retrieving list of policies for role [%v] : %v", *role.RoleName, err)
					complianceEvaluation := evaltypes.ComplianceEvaluation{
						AccountId:    accountId,
						ResourceType: evaltypes.AWS_IAM_ROLE,
						Arn:          *role.Arn,
						Compliance:   configServiceTypes.ComplianceTypeInsufficientData,
						ErrMsg:       err.Error(),
						Timestamp:    time.Now(),
						Annotation:   "",
					}
					processingErr := ProcessingError{
						Wg:                   e.wg,
						ComplianceEvaluation: complianceEvaluation,
						Result:               resultsBuffer,
						Message:              err.Error(),
					}
					HandleError(processingErr)
					return
				}
				// loop through policy documents and check for compliance
				for _, policyName := range listRolePoliciesPage.PolicyNames {
					e.Logger.Debugf("processing compliance check for policy [%v]", policyName)
					// retrieve policy document for policy
					getPolicyDocumentOutput, err := iamClient.GetRolePolicy(context.Background(), &iam.GetRolePolicyInput{
						PolicyName: aws.String(policyName),
						RoleName:   role.RoleName,
					})
					// check for errors
					if err != nil {
						e.Logger.Errorf("error retrieving policy document for policy [%v] : %v", policyName, err)
						complianceEvaluation := evaltypes.ComplianceEvaluation{
							AccountId:    accountId,
							ResourceType: evaltypes.AWS_IAM_ROLE,
							Arn:          *role.Arn,
							Compliance:   configServiceTypes.ComplianceTypeInsufficientData,
							ErrMsg:       err.Error(),
							Timestamp:    time.Now(),
							Annotation:   "",
						}
						processingErr := ProcessingError{
							Wg:                   e.wg,
							ComplianceEvaluation: complianceEvaluation,
							Result:               resultsBuffer,
							Message:              err.Error(),
						}
						HandleError(processingErr)
						return
					}
					policyDocument := *getPolicyDocumentOutput.PolicyDocument
					// check if policy document is compliant
					isCompliantResult, err := e.IsCompliant(accessAnalyzerClient, policyDocument, e.restrictedActions)
					// check for errors
					if err != nil {
						e.Logger.Errorf("error checking compliance for policy [%v] : %v", policyName, err)
						complianceEvaluation := evaltypes.ComplianceEvaluation{
							AccountId:    accountId,
							ResourceType: evaltypes.AWS_IAM_ROLE,
							Arn:          *role.Arn,
							ErrMsg:       err.Error(),
							Timestamp:    time.Now(),
							Annotation:   "",
						}
						processingErr := ProcessingError{
							Wg:                   e.wg,
							ComplianceEvaluation: complianceEvaluation,
							Result:               resultsBuffer,
							Message:              err.Error(),
						}
						HandleError(processingErr)
					}
					// send compliance result to results channel
					e.wg.Add(1)
					resultsBuffer <- evaltypes.ComplianceEvaluation{
						AccountId:  accountId,
						Arn:        *role.Arn,
						Compliance: isCompliantResult.Compliance,
					}
				}
			}
		}
	}
}

// process compliance for iam users
func (e *_Evaluator) ProcessComplianceForUsers(accountId string, resultsBuffer chan<- evaltypes.ComplianceEvaluation) {
	defer e.wg.Done()
	iamClient := e.GetAwsIamClient(accountId)
	accessAnalyzerClient := e.GetAwsAccessAnalyzerClient(accountId)
	// list all policies for users
	listUserPaginator := iam.NewListUsersPaginator(iamClient, &iam.ListUsersInput{})
	for listUserPaginator.HasMorePages() {
		listUserPage, err := listUserPaginator.NextPage(context.Background())
		// check for errors
		if err != nil {
			e.Logger.Errorf("error retrieving list of users : %v", err)
			complianceEvaluation := evaltypes.ComplianceEvaluation{
				AccountId:    accountId,
				ResourceType: evaltypes.NOT_SPECIFIED,
				Arn:          "",
				Compliance:   configServiceTypes.ComplianceTypeInsufficientData,
				ErrMsg:       err.Error(),
				Timestamp:    time.Now(),
				Annotation:   "",
			}
			processingErr := ProcessingError{
				Wg:                   e.wg,
				ComplianceEvaluation: complianceEvaluation,
				Result:               resultsBuffer,
				Message:              err.Error(),
			}
			HandleError(processingErr)
			return
		}
		for _, user := range listUserPage.Users {
			e.Logger.Debugf("processing compliance check for user [%v]", *user.UserName)
			// loop through all policies attached to user and retrieve policy document
			listUserPolicyPaginator := iam.NewListUserPoliciesPaginator(iamClient, &iam.ListUserPoliciesInput{
				UserName: user.UserName,
			})
			for listUserPolicyPaginator.HasMorePages() {
				listUserPoliciesPage, err := listUserPolicyPaginator.NextPage(context.Background())
				// check for errors
				if err != nil {
					e.Logger.Errorf("error retrieving list of policies for user [%v] : %v", *user.UserName, err)
					complianceEvaluation := evaltypes.ComplianceEvaluation{
						AccountId:    accountId,
						ResourceType: evaltypes.AWS_IAM_USER,
						Arn:          *user.Arn,
						Compliance:   configServiceTypes.ComplianceTypeInsufficientData,
						ErrMsg:       err.Error(),
						Timestamp:    time.Now(),
						Annotation:   "",
					}
					processingErr := ProcessingError{
						Wg:                   e.wg,
						ComplianceEvaluation: complianceEvaluation,
						Result:               resultsBuffer,
						Message:              err.Error(),
					}
					HandleError(processingErr)
					return
				}
				// loop through policy documents and check for compliance
				for _, policyName := range listUserPoliciesPage.PolicyNames {
					e.Logger.Debugf("processing compliance check for policy [%v]", policyName)
					// retrieve policy document for policy
					getPolicyDocumentOutput, err := iamClient.GetUserPolicy(context.Background(), &iam.GetUserPolicyInput{
						PolicyName: aws.String(policyName),
						UserName:   user.UserName,
					})
					// check for errors
					if err != nil {
						e.Logger.Errorf("error retrieving policy document for policy [%v] : %v", policyName, err)
						complianceEvaluation := evaltypes.ComplianceEvaluation{
							AccountId:    accountId,
							ResourceType: evaltypes.AWS_IAM_USER,
							Arn:          *user.Arn,
							Compliance:   configServiceTypes.ComplianceTypeInsufficientData,
							ErrMsg:       err.Error(),
							Timestamp:    time.Now(),
							Annotation:   "",
						}
						processingErr := ProcessingError{
							Wg:                   e.wg,
							ComplianceEvaluation: complianceEvaluation,
							Result:               resultsBuffer,
							Message:              err.Error(),
						}
						HandleError(processingErr)
						return
					}
					policyDocument := *getPolicyDocumentOutput.PolicyDocument
					// check if policy document is compliant
					isCompliantResult, err := e.IsCompliant(accessAnalyzerClient, policyDocument, e.restrictedActions)
					// check for errors
					if err != nil {
						e.Logger.Errorf("error checking compliance for policy [%v] : %v", policyName, err)
						complianceEvaluation := evaltypes.ComplianceEvaluation{
							AccountId:    "",
							ResourceType: evaltypes.AWS_IAM_USER,
							Arn:          *user.Arn,
							Compliance:   configServiceTypes.ComplianceTypeInsufficientData,
							ErrMsg:       err.Error(),
							Timestamp:    time.Now(),
							Annotation:   "",
						}
						processingErr := ProcessingError{
							Wg:                   e.wg,
							ComplianceEvaluation: complianceEvaluation,
							Result:               resultsBuffer,
							Message:              err.Error(),
						}
						HandleError(processingErr)
					}
					// send compliance result to results channel
					e.wg.Add(1)
					resultsBuffer <- evaltypes.ComplianceEvaluation{
						AccountId:  accountId,
						Arn:        *user.Arn,
						Compliance: isCompliantResult.Compliance,
					}
				}
			}
		}
	}
}

// process compliance for iam users and iam roles
func (e *_Evaluator) ProcessComplianceForAll(accountId string, resultsBuffer chan<- evaltypes.ComplianceEvaluation) {
	defer e.wg.Done()
	e.wg.Add(1)
	go e.ProcessComplianceForUsers(accountId, resultsBuffer)
	e.wg.Add(1)
	go e.ProcessComplianceForRoles(accountId, resultsBuffer)
}

// check if policy document is compliant
func (e *_Evaluator) IsCompliant(client *accessanalyzer.Client, policyDocument string, restrictedActions []string) (evaltypes.ComplianceResult, error) {
	input := accessanalyzer.CheckAccessNotGrantedInput{
		Access: []accessAnalyzerTypes.Access{
			{
				Actions: e.restrictedActions,
			},
		},
		PolicyDocument: aws.String(policyDocument),
		PolicyType:     accessAnalyzerTypes.AccessCheckPolicyType(accessAnalyzerTypes.PolicyTypeIdentityPolicy),
	}
	// check if policy document is compliant
	output, err := client.CheckAccessNotGranted(context.Background(), &input)
	// check for errors
	if err != nil {
		e.Logger.Errorf("error checking compliance for policy document : %v", err)
		return evaltypes.ComplianceResult{}, err
	}
	if output.Result == accessAnalyzerTypes.CheckAccessNotGrantedResultPass {
		return evaltypes.ComplianceResult{
			Compliance: configServiceTypes.ComplianceTypeCompliant,
			Reasons:    output.Reasons,
			Message:    *output.Message,
		}, nil
	}
	return evaltypes.ComplianceResult{
		Compliance: configServiceTypes.ComplianceTypeNonCompliant,
		Reasons:    output.Reasons,
		Message:    *output.Message,
	}, nil
}

// ###############################################################################################################
// AWS CONFIG INTERFACE METHODS
// ###############################################################################################################

// send evaluation to AWS config
func (e *_Evaluator) SendEvaluations(evaluations []configServiceTypes.Evaluation) {
	e.Logger.Debugf("sending evaluations to AWS config")
	// send evaluation to AWS config
	resultToken := e.GetResultToken()
	_, err := e.configClient.PutEvaluations(context.Background(), &configservice.PutEvaluationsInput{
		ResultToken: aws.String(resultToken),
		Evaluations: evaluations,
		TestMode:    false,
	})
	// return errors
	if err != nil {
		e.Logger.Errorf("error sending evaluations to AWS config : %v", err)
		evaluationErr := EvaluationError{
			Message: err.Error(),
		}
		HandleError(evaluationErr)
	}
}

// ###############################################################################################################
// DATA VALIDATION INTERFACE METHODS
// ###############################################################################################################

// validate action from configuration file
func (e *_Evaluator) IsValidAction(action string) bool {
	// IAM action pattern: <service-namespace>:<action-name>
	iamActionRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+:[a-zA-Z0-9_\*]+$`)
	return iamActionRegex.MatchString(action)
}

// validate scope
func (e *_Evaluator) IsValidScope(scope string) bool {
	if strings.ToLower(scope) == "roles" || strings.ToLower(scope) == "users" || strings.ToLower(scope) == "all" {
		return true
	}
	e.Logger.Errorf("invalid scope [%v]", scope)
	return false
}

// ###############################################################################################################
// GETTER & SETTER INTERFACE METHODS
// ###############################################################################################################

// get logger
func (e *_Evaluator) GetLogger() logger.Logger {
	return e.Logger
}

// return AWS Config client
func (e *_Evaluator) GetAwsConfigClient() *configservice.Client {
	return e.configClient
}

// set AWS Config client
func (e *_Evaluator) SetAwsConfigClient(client *configservice.Client) {
	e.configClient = client
}

// return AWS IAM client
func (e *_Evaluator) GetAwsIamClient(accountId string) *iam.Client {
	return e.iamClientMap[accountId]
}

// set AWS IAM client
func (e *_Evaluator) SetAwsIamClient(accountId string, client *iam.Client) {
	e.iamClientMap[accountId] = client
}

// return AWS Access Analyzer client
func (e *_Evaluator) GetAwsAccessAnalyzerClient(accountId string) *accessanalyzer.Client {
	return e.accessAnalyzerClientMap[accountId]
}

// set AWS Access Analyzer client
func (e *_Evaluator) SetAwsAccessAnalyzerClient(accountId string, client *accessanalyzer.Client) {
	e.accessAnalyzerClientMap[accountId] = client
}

// return restricted actions
func (e *_Evaluator) GetRestrictedActions() []string {
	return e.restrictedActions
}

// append restricted action
func (e *_Evaluator) AppendRestrictedAction(action string) {
	e.restrictedActions = append(e.restrictedActions, action)
}

// set result token
func (e *_Evaluator) SetResultToken(token string) {
	e.resultToken = token
}

// get result token
func (e *_Evaluator) GetResultToken() string {
	return e.resultToken
}

// set scope
func (e *_Evaluator) SetScope(scope string) {
	e.scope = scope
}

// get scope
func (e *_Evaluator) GetScope() string {
	return e.scope
}
