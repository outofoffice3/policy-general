package evaluator

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/outofoffice3/policy-general/pkg/pgevents"
	"github.com/outofoffice3/policy-general/pkg/pgtypes"
)

/*

Evaluator interface is responsible for the following :

- Handling serialized config event from cloudwatch
- Validating that the actions from the configuration file are valid
- Retrieving IAM clients to use for cross account access
- Checking compliance of a policy document
- Sending evaluation response to AWS Config

*/

var (
	policyGeneral Evaluator
)

type Evaluator interface {
	// entry point for evaluator interface.  Handles serialized config event from cloudwatch
	HandleConfigEvent(event pgevents.ConfigEvent) []pgtypes.ComplianceEvaluation
	// validate restricted actions from configuration file
	IsValidAction(action string) bool
	// validate scope value
	IsValidScope(scope string) bool
	// evaulate if a policy document is compliant
	IsCompliant(client *accessanalyzer.Client, policyDocument string, restrictedActions []string) (pgtypes.ComplianceResult, error)
	// send evaluation response to AWS config
	SendEvaluations(evaluations []configServiceTypes.Evaluation) error
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

// initialize evaluator
func Init(logger logger.Logger) {
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
		variable CONFIG_FILE_KEY.  Read the file from s3 and serialze into the pgtypes.Config type.

		type Config struct {
			AwsAccounts []AwsAccount `json:"awsAccounts"`
			Actions     []string     `json:"actions"`
			Scope       string       `json:"scope"`
		}

		Load the client map with *iam.Clients that all have assumed the respective role from the Config.
		They [key] = accound id and [value] = *iam.Client.  Set the scope based on the config file.
		Validate each action from the config file.
	*/
	logger.Infof("evaluator init started")
	policyGeneral := NewEvaluator()
	policyGeneral.Logger = logger

	evaluatorConfigBucketName := os.Getenv("CONFIG_FILE_BUCKET_NAME")
	evaluatorConfigObjectKey := os.Getenv("CONFIG_FILE_KEY")
	cfg, err := config.LoadDefaultConfig(context.Background())
	// return errors
	if err != nil {
		initErr := InitError{
			message: err.Error(),
		}
		handleError(initErr)
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
			message: err.Error(),
		}
		handleError(initErr)
	}

	objectContent, err := io.ReadAll(getObjectOutput.Body)
	// return errors
	if err != nil {
		initErr := InitError{
			message: err.Error(),
		}
		handleError(initErr)
	}

	var policyGeneralConfig pgtypes.Config
	err = json.Unmarshal(objectContent, &policyGeneralConfig)
	// return errors
	if err != nil {
		initErr := InitError{
			message: err.Error(),
		}
		handleError(initErr)
	}

	// validate scope from config file
	if !policyGeneral.IsValidScope(policyGeneralConfig.Scope) {
		logger.Errorf("invalid scope [%v] in config file", policyGeneralConfig.Scope)
		handleError(InitError{
			message: "invalid scope value in config file",
		})
	}
	policyGeneral.SetScope(policyGeneralConfig.Scope)

	// initialize aws config client
	policyGeneral.configClient = configservice.NewFromConfig(cfg)
	// get assume role provider, assume the respective role and load client map
	stsClient := sts.NewFromConfig(cfg)
	for _, awsAccount := range policyGeneralConfig.AWSAccounts {
		creds := stscreds.NewAssumeRoleProvider(stsClient, awsAccount.RoleName)
		cfg.Credentials = aws.NewCredentialsCache(creds)
		iamClient := iam.NewFromConfig(cfg)
		policyGeneral.iamClientMap[awsAccount.AccountID] = iamClient
		logger.Debugf("iam client [%v] loaded to map with role [%v]", awsAccount.AccountID, awsAccount.RoleName)
		accessAnalzyerClient := accessanalyzer.NewFromConfig(cfg)
		policyGeneral.accessAnalyzerClientMap[awsAccount.AccountID] = accessAnalzyerClient
		logger.Debugf("access analyzer client [%v] loaded to map with role [%v]", awsAccount.AccountID, awsAccount.RoleName)
	}
	logger.Debugf("iam & access analyzer clients successfully loaded to evaluator interface client maps")

	// validate actions from config file
	for _, action := range policyGeneralConfig.RestrictedActions {
		if !policyGeneral.IsValidAction(action) {
			logger.Errorf("invalid action [%v] in config file", action)
			handleError(InitError{
				message: "invalid restriced action in config file",
			})
		}
		// add action to policy general
		policyGeneral.restrictedActions = append(policyGeneral.restrictedActions, action)
		logger.Debugf("action [%v] added to policy general")
	}
	logger.Infof("evaluator package successfully initialized")
}

// create new evaluator
func NewEvaluator() *_Evaluator {
	return &_Evaluator{
		wg:                &sync.WaitGroup{},
		scope:             "",
		iamClientMap:      make(map[string]*iam.Client),
		Logger:            nil,
		restrictedActions: nil,
	}
}

// set scope
func (e *_Evaluator) SetScope(scope string) {
	e.scope = scope
}

// handle config event
func (e *_Evaluator) HandleConfigEvent(event pgevents.ConfigEvent) []pgtypes.ComplianceEvaluation {
	e.resultToken = event.ResultToken                                          // set result token
	resultChan := make(chan pgtypes.ComplianceEvaluation, len(e.iamClientMap)) // result channel to send / receive results on
	// loop through accounts in client map and process compliance check in go routine
	for accountId := range e.iamClientMap {
		e.wg.Add(1)                                        // increment wait group counter
		go e.ProcessComplianceCheck(accountId, resultChan) // process check in go routine
		e.Logger.Debugf("processing compliance check for account [%v]", accountId)
	}

	// close go routine channel when all compliance checks complete
	finishSignal := make(chan pgtypes.FinishSignal)
	go func(chan pgtypes.ComplianceEvaluation) {
		<-finishSignal
		e.Logger.Debugf("closing results channel")
		close(resultChan)
	}(resultChan)

	// read results from results channel
	var batchEvaluations []configServiceTypes.Evaluation
	maxBatchSize := 100
	currentIndex := 0
	for result := range resultChan {
		e.Logger.Debugf("result received : %v", result)
		if result.ErrMsg != "" {
			e.Logger.Errorf("error processing compliance check for account [%v] : %v", result.AccountId, result.ErrMsg)
		}
		evaulation := configServiceTypes.Evaluation{
			ComplianceResourceType: aws.String(result.ResourceType),
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
			err := e.SendEvaluations(batchEvaluations)
			if err != nil {
				executionErr := ExecutionError{
					service: AWS_CONFIG,
					message: err.Error(),
				}
				handleError(executionErr)
			}
			currentIndex = 0
			continue
		}
	}
	finishSignal <- pgtypes.FinishSignal{}
	// send remaining results to aws config
	err := e.SendEvaluations(batchEvaluations)
	if err != nil {
		executionErr := ExecutionError{
			service: AWS_CONFIG,
			message: err.Error(),
		}
		handleError(executionErr)
	}
	return nil
}

// process compliance check for an aws account
func (e *_Evaluator) ProcessComplianceCheck(accountId string, resultChan chan<- pgtypes.ComplianceEvaluation) error {
	defer e.wg.Done()
	switch strings.ToLower(e.scope) {
	case "roles":
		e.wg.Add(1)
		go e.ProcessComplianceForRoles(accountId, resultChan)
	case "users":
		e.wg.Add(1)
		go e.ProcessComplianceForUsers(accountId, resultChan)
	case "all":
		e.wg.Add(1)
		go e.ProcessComplianceForAll(accountId, resultChan)
	}
	return nil
}

// process compliance for iam roles
func (e *_Evaluator) ProcessComplianceForRoles(accountId string, resultChan chan<- pgtypes.ComplianceEvaluation) {
	defer e.wg.Done()
	iamClient, err := e.getIamClient(accountId)
	// return errors
	if err != nil {
		e.Logger.Errorf("error retrieving iam client for account [%v] : %v", accountId, err)
		complianceEvaluation := pgtypes.ComplianceEvaluation{
			AccountId:    accountId,
			ResourceType: AWS_IAM_ROLE,
			Arn:          "",
			Compliance:   configServiceTypes.ComplianceType(NOT_APPLICABLE),
			ErrMsg:       err.Error(),
			Timestamp:    time.Now(),
			Annotation:   "",
		}
		processingErr := ProcessingError{
			complianceEvaluation: complianceEvaluation,
			result:               resultChan,
			message:              err.Error(),
		}
		handleError(processingErr)
		return
	}
	accessAnalyzerClient, err := e.getAccessAnalyzerClient(accountId)
	// return errors
	if err != nil {
		e.Logger.Errorf("error retrieving access analyzer client for account [%v] : %v", accountId, err)
		complianceEvaluation := pgtypes.ComplianceEvaluation{
			AccountId:    accountId,
			ResourceType: AWS_IAM_ROLE,
			Arn:          "",
			Compliance:   configServiceTypes.ComplianceType(NOT_APPLICABLE),
			ErrMsg:       err.Error(),
			Timestamp:    time.Now(),
			Annotation:   "",
		}
		processingErr := ProcessingError{
			complianceEvaluation: complianceEvaluation,
			result:               resultChan,
			message:              err.Error(),
		}
		handleError(processingErr)
		return
	}
	// list all policies for roles
	listRolePaginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{})
	for listRolePaginator.HasMorePages() {
		listRolePage, err := listRolePaginator.NextPage(context.Background())
		// check for errors
		if err != nil {
			e.Logger.Errorf("error retrieving list of roles : %v", err)
			complianceEvaluation := pgtypes.ComplianceEvaluation{
				AccountId:    accountId,
				ResourceType: AWS_IAM_ROLE,
				Arn:          "",
				Compliance:   configServiceTypes.ComplianceType(NOT_APPLICABLE),
				ErrMsg:       err.Error(),
				Timestamp:    time.Now(),
				Annotation:   "",
			}
			processingErr := ProcessingError{
				complianceEvaluation: complianceEvaluation,
				result:               resultChan,
				message:              err.Error(),
			}
			handleError(processingErr)
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
					complianceEvaluation := pgtypes.ComplianceEvaluation{
						AccountId:    accountId,
						ResourceType: AWS_IAM_ROLE,
						Arn:          *role.Arn,
						Compliance:   configServiceTypes.ComplianceType(NOT_APPLICABLE),
						ErrMsg:       err.Error(),
						Timestamp:    time.Now(),
						Annotation:   "",
					}
					processingErr := ProcessingError{
						complianceEvaluation: complianceEvaluation,
						result:               resultChan,
						message:              err.Error(),
					}
					handleError(processingErr)
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
						complianceEvaluation := pgtypes.ComplianceEvaluation{
							AccountId:    accountId,
							ResourceType: AWS_IAM_ROLE,
							Arn:          *role.Arn,
							Compliance:   configServiceTypes.ComplianceType(NOT_APPLICABLE),
							ErrMsg:       err.Error(),
							Timestamp:    time.Now(),
							Annotation:   "",
						}
						processingErr := ProcessingError{
							complianceEvaluation: complianceEvaluation,
							result:               resultChan,
							message:              err.Error(),
						}
						handleError(processingErr)
						return
					}
					policyDocument := *getPolicyDocumentOutput.PolicyDocument
					// check if policy document is compliant
					isCompliantResult, err := e.IsCompliant(accessAnalyzerClient, policyDocument, e.restrictedActions)
					// check for errors
					if err != nil {
						e.Logger.Errorf("error checking compliance for policy [%v] : %v", policyName, err)
						complianceEvaluation := pgtypes.ComplianceEvaluation{
							AccountId:    "",
							ResourceType: AWS_IAM_ROLE,
							Arn:          *role.Arn,
							ErrMsg:       err.Error(),
							Timestamp:    time.Now(),
							Annotation:   "",
						}
						processingErr := ProcessingError{
							complianceEvaluation: complianceEvaluation,
							result:               resultChan,
							message:              err.Error(),
						}
						handleError(processingErr)
					}
					resultChan <- pgtypes.ComplianceEvaluation{
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
func (e *_Evaluator) ProcessComplianceForUsers(accountId string, resultChan chan<- pgtypes.ComplianceEvaluation) {
	defer e.wg.Done()
	iamClient, err := e.getIamClient(accountId)
	// return errors
	if err != nil {
		e.Logger.Errorf("error retrieving iam client for account [%v] : %v", accountId, err)
		complianceEvaluation := pgtypes.ComplianceEvaluation{
			AccountId: accountId,
			Arn:       "",
			ErrMsg:    err.Error(),
		}
		processingErr := ProcessingError{
			complianceEvaluation: complianceEvaluation,
			result:               resultChan,
			message:              err.Error(),
		}
		handleError(processingErr)
		return
	}
	accessAnalyzerClient, err := e.getAccessAnalyzerClient(accountId)
	// return errors
	if err != nil {
		e.Logger.Errorf("error retrieving access analyzer client for account [%v] : %v", accountId, err)
		complianceEvaluation := pgtypes.ComplianceEvaluation{
			AccountId: accountId,
			Arn:       "",
			ErrMsg:    err.Error(),
		}
		processingErr := ProcessingError{
			complianceEvaluation: complianceEvaluation,
			result:               resultChan,
			message:              err.Error(),
		}
		handleError(processingErr)
		return
	}
	// list all policies for users
	listUserPaginator := iam.NewListUsersPaginator(iamClient, &iam.ListUsersInput{})
	for listUserPaginator.HasMorePages() {
		listUserPage, err := listUserPaginator.NextPage(context.Background())
		// check for errors
		if err != nil {
			e.Logger.Errorf("error retrieving list of users : %v", err)
			complianceEvaluation := pgtypes.ComplianceEvaluation{
				AccountId: accountId,
				Arn:       "",
				ErrMsg:    err.Error(),
			}
			processingErr := ProcessingError{
				complianceEvaluation: complianceEvaluation,
				result:               resultChan,
				message:              err.Error(),
			}
			handleError(processingErr)
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
					complianceEvaluation := pgtypes.ComplianceEvaluation{
						AccountId: accountId,
						Arn:       *user.Arn,
						ErrMsg:    err.Error(),
					}
					processingErr := ProcessingError{
						complianceEvaluation: complianceEvaluation,
						result:               resultChan,
						message:              err.Error(),
					}
					handleError(processingErr)
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
						complianceEvaluation := pgtypes.ComplianceEvaluation{
							AccountId: accountId,
							Arn:       *user.Arn,
							ErrMsg:    err.Error(),
						}
						processingErr := ProcessingError{
							complianceEvaluation: complianceEvaluation,
							result:               resultChan,
							message:              err.Error(),
						}
						handleError(processingErr)
						return
					}
					policyDocument := *getPolicyDocumentOutput.PolicyDocument
					// check if policy document is compliant
					isCompliantResult, err := e.IsCompliant(accessAnalyzerClient, policyDocument, e.restrictedActions)
					// check for errors
					if err != nil {
						e.Logger.Errorf("error checking compliance for policy [%v] : %v", policyName, err)
						complianceEvaluation := pgtypes.ComplianceEvaluation{
							AccountId: "",
							Arn:       *user.Arn,
							ErrMsg:    err.Error(),
						}
						processingErr := ProcessingError{
							complianceEvaluation: complianceEvaluation,
							result:               resultChan,
							message:              err.Error(),
						}
						handleError(processingErr)
					}
					resultChan <- pgtypes.ComplianceEvaluation{
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
func (e *_Evaluator) ProcessComplianceForAll(accountId string, resultChan chan<- pgtypes.ComplianceEvaluation) {
	defer e.wg.Done()
	e.wg.Add(1)
	go e.ProcessComplianceForUsers(accountId, resultChan)
	e.wg.Add(1)
	go e.ProcessComplianceForRoles(accountId, resultChan)
}

// check if policy document is compliant
func (e *_Evaluator) IsCompliant(client *accessanalyzer.Client, policyDocument string, restrictedActions []string) (pgtypes.ComplianceResult, error) {
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
		return pgtypes.ComplianceResult{}, err
	}
	if output.Result == accessAnalyzerTypes.CheckAccessNotGrantedResultPass {
		return pgtypes.ComplianceResult{
			Compliance: configServiceTypes.ComplianceType(COMPLIANT),
			Reasons:    output.Reasons,
			Message:    *output.Message,
		}, nil
	}
	return pgtypes.ComplianceResult{
		Compliance: configServiceTypes.ComplianceType(NON_COMPLIANT),
		Reasons:    output.Reasons,
		Message:    *output.Message,
	}, nil
}

// validate scope
func (e *_Evaluator) IsValidScope(scope string) bool {
	if strings.ToLower(scope) == "roles" || strings.ToLower(scope) == "users" || strings.ToLower(scope) == "all" {
		return true
	}
	e.Logger.Errorf("invalid scope [%v]", scope)
	return false
}

// send evaluation to AWS config
func (e *_Evaluator) SendEvaluations(evaluations []configServiceTypes.Evaluation) error {
	e.Logger.Debugf("sending evaluations to AWS config")
	// send evaluation to AWS config
	_, err := e.configClient.PutEvaluations(context.Background(), &configservice.PutEvaluationsInput{
		ResultToken: &e.resultToken,
		Evaluations: evaluations,
		TestMode:    false,
	})
	// return errors
	if err != nil {
		e.Logger.Errorf("error sending evaluations to AWS config : %v", err)
		evaluationErr := EvaluationError{
			message: err.Error(),
		}
		handleError(evaluationErr)
	}
	return nil
}

// validate action from configuration file
func (e *_Evaluator) IsValidAction(action string) bool {
	// IAM action pattern: <service-namespace>:<action-name>
	iamActionRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+:[a-zA-Z0-9_\*]+$`)
	return iamActionRegex.MatchString(action)
}

// retrieve iam client by account id
func (e *_Evaluator) getIamClient(accountId string) (*iam.Client, error) {
	if client, ok := e.iamClientMap[accountId]; ok {
		e.Logger.Debugf("retrieving iam client for account [%v]", accountId)
		return client, nil
	}
	e.Logger.Errorf("no iam client found for account [%v]", accountId)
	return nil, errors.New("no iam client found for account [" + accountId + "]")
}

// retrieve access analyzer client by account id
func (e *_Evaluator) getAccessAnalyzerClient(accountId string) (*accessanalyzer.Client, error) {
	if client, ok := e.accessAnalyzerClientMap[accountId]; ok {
		e.Logger.Debugf("retrieving access analyzer client for account [%v]", accountId)
		return client, nil
	}
	e.Logger.Errorf("no access analyzer client found for account [%v]", accountId)
	return nil, errors.New("no access analyzer client found for account [" + accountId + "]")
}

// get policyGeneral
func GetPolicyGeneral() Evaluator {
	return policyGeneral
}
