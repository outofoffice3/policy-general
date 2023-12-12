package iampolicyevaluator

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/configservice"

	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/outofoffice3/policy-general/internal/awsclientmgr"
	"github.com/outofoffice3/policy-general/internal/entrymgr"
	"github.com/outofoffice3/policy-general/internal/exporter"
	"github.com/outofoffice3/policy-general/internal/shared"
)

type IAMPolicyEvaluator interface {

	// ###############################################################################################################
	// POLICY EVALUATION METHODS
	// ###############################################################################################################

	// check iam identity policies for restricted actions
	CheckNoAccess(scope string, restrictedActions []string, accountId string, results chan shared.ComplianceEvaluation) error
	// send compliance evaluation to AWS config
	SendEvaluations(evaluations []configServiceTypes.Evaluation)
	// check if iam policy document contains restircted actions

	// ###############################################################################################################
	// MANAGING WAIT GROUP METHODS
	// ###############################################################################################################

	// increment wait group
	IncrementWaitGroup(value int)
	// decrement wait group
	DecrementWaitGroup()
	// wait for evaluator to finish processing
	Wait()

	// ###############################################################################################################
	// GETTER & SETTER METHODS
	// ###############################################################################################################

	// get aws client mgr
	GetAWSClientMgr() awsclientmgr.AWSClientMgr
	// get exporter
	GetExporter() exporter.Exporter
	// set result token
	SetResultToken(token string)
	// get result token
	GetResultToken() string
	// set scope
	SetScope(scope string)
	// get scope
	GetScope() string
	// set restricted actions
	SetRestrictedActions(restrictedActions []string)
	// get restricted actions
	GetRestrictedActions() []string
}

type _IAMPolicyEvaluator struct {
	wg                *sync.WaitGroup
	resultToken       string
	scope             string
	accountId         string
	restrictedActions []string
	results           chan shared.ComplianceEvaluation
	awsClientMgr      awsclientmgr.AWSClientMgr
	exporter          exporter.Exporter
}

type IAMPolicyEvaluatorInitConfig struct {
	Cfg       aws.Config
	Config    shared.Config
	AccountId string
}

// returns an instance of iam policy evaluator
func Init(config IAMPolicyEvaluatorInitConfig) IAMPolicyEvaluator {

	// create entry mgr
	entryMgr := entrymgr.Init()

	// create aws client mgr
	awsClientMgr := awsclientmgr.Init(awsclientmgr.AWSClientMgrInitConfig{
		Cfg:       config.Cfg,
		Config:    config.Config,
		AccountId: config.AccountId,
	})

	// creeate exporter
	exporter, err := exporter.Init(exporter.ExporterInitConfig{
		AwsClientMgr: awsClientMgr,
		EntryMgr:     entryMgr,
		AccountId:    config.AccountId,
	})
	// return errors
	if err != nil {
		log.Printf("error initializing exporter : %v", err)
		return nil
	}

	// create iam policy evaluator
	iamPolicyEvaluator := NewIAMPolicyEvaluator(IAMPolicyEvaluatorInput{
		wg:                &sync.WaitGroup{},
		awsClientMgr:      awsClientMgr,
		exporter:          exporter,
		accountID:         config.AccountId,
		restrictedActions: config.Config.RestrictedActions,
		scope:             config.Config.Scope,
	})
	log.Println("iampolicyevaluator init success")
	return iamPolicyEvaluator

}

// input to create a new iam policy evaluator
type IAMPolicyEvaluatorInput struct {
	wg                *sync.WaitGroup
	awsClientMgr      awsclientmgr.AWSClientMgr
	exporter          exporter.Exporter
	accountID         string
	scope             string
	restrictedActions []string
}

// creates a new iam policy evaluator
func NewIAMPolicyEvaluator(input IAMPolicyEvaluatorInput) IAMPolicyEvaluator {
	return &_IAMPolicyEvaluator{
		wg:                input.wg,
		resultToken:       "",
		scope:             input.scope,
		accountId:         input.accountID,
		restrictedActions: input.restrictedActions,
		results:           make(chan shared.ComplianceEvaluation, 100),
		awsClientMgr:      input.awsClientMgr,
		exporter:          input.exporter,
	}
}

// ###############################################################################################################
// POLICY EVALUATION METHODS
// ###############################################################################################################

func (i *_IAMPolicyEvaluator) processRoleCompliance(restrictedActions []string, accountId string, resultsBuffer chan shared.ComplianceEvaluation) {
	defer i.wg.Done()

	// retrieve sdk iam and access analyzer clients
	awscm := i.GetAWSClientMgr()
	client, _ := awscm.GetSDKClient(accountId, awsclientmgr.IAM)
	iamClient := client.(*iam.Client)
	aaClient, _ := awscm.GetSDKClient(accountId, awsclientmgr.AA)
	accessAnalyzerClient := aaClient.(*accessanalyzer.Client)

	// list all policies for roles
	listRolePaginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{})
	for listRolePaginator.HasMorePages() {
		listRolePage, err := listRolePaginator.NextPage(context.Background())
		// check for errors
		if err != nil {
			log.Printf("error retrieving list of roles : [%v] \n", err)
			complianceEvaluation := shared.ComplianceEvaluation{
				AccountId:    accountId,
				ResourceType: shared.NotSpecified,
				Arn:          "",
				ComplianceResult: shared.ComplianceResult{
					Compliance: configServiceTypes.ComplianceTypeInsufficientData,
					Reasons:    nil,
					Message:    "",
				},
				ErrMsg:    err.Error(),
				Timestamp: time.Now(),
			}
			processingErr := ProcessingError{
				ComplianceEvaluation: complianceEvaluation,
				ResultsBuffer:        resultsBuffer,
				Message:              err.Error(),
			}
			HandleError(processingErr, i)
			return
		}
		for _, role := range listRolePage.Roles {
			log.Printf("processing compliance check for role [%v]\n", *role.RoleName)
			// loop through all policies attached to role and retrieve policy document
			listRolePolicyPaginator := iam.NewListRolePoliciesPaginator(iamClient, &iam.ListRolePoliciesInput{
				RoleName: role.RoleName,
			})
			for listRolePolicyPaginator.HasMorePages() {
				listRolePoliciesPage, err := listRolePolicyPaginator.NextPage(context.Background())
				// check for errors
				if err != nil {
					log.Printf("error retrieving list of policies for role [%v] : [%v] \n ", *role.RoleName, err)
					complianceEvaluation := shared.ComplianceEvaluation{
						AccountId:    accountId,
						ResourceType: shared.AwsIamRole,
						Arn:          *role.Arn,
						ComplianceResult: shared.ComplianceResult{
							Compliance: configServiceTypes.ComplianceTypeNotApplicable,
							Reasons:    nil,
							Message:    "",
						},
						ErrMsg:    err.Error(),
						Timestamp: time.Now(),
					}
					processingErr := ProcessingError{
						ComplianceEvaluation: complianceEvaluation,
						ResultsBuffer:        resultsBuffer,
						Message:              err.Error(),
					}
					HandleError(processingErr, i)
					return
				}
				// loop through policy documents and check for compliance
				for _, policyName := range listRolePoliciesPage.PolicyNames {
					log.Printf("processing compliance check for policy [%v]\n", policyName)
					// retrieve policy document for policy
					getPolicyDocumentOutput, err := iamClient.GetRolePolicy(context.Background(), &iam.GetRolePolicyInput{
						PolicyName: aws.String(policyName),
						RoleName:   role.RoleName,
					})
					// check for errors
					if err != nil {
						log.Printf("error retrieving policy document for policy [%v] : [%v]\n", policyName, err)
						complianceEvaluation := shared.ComplianceEvaluation{
							AccountId:    accountId,
							ResourceType: shared.AwsIamRole,
							Arn:          *role.Arn,
							ComplianceResult: shared.ComplianceResult{
								Compliance: configServiceTypes.ComplianceTypeNotApplicable,
								Reasons:    nil,
								Message:    "",
							},
							ErrMsg:    err.Error(),
							Timestamp: time.Now(),
						}
						processingErr := ProcessingError{
							ComplianceEvaluation: complianceEvaluation,
							ResultsBuffer:        resultsBuffer,
							Message:              err.Error(),
						}
						HandleError(processingErr, i)
						return
					}
					policyDocument := *getPolicyDocumentOutput.PolicyDocument
					log.Printf("policy name [%v], policy document [%+s]\n", policyName, policyDocument)
					// check if policy document is compliant
					isCompliantResult, err := shared.IsCompliant(accessAnalyzerClient, policyDocument, restrictedActions)
					// check for errors
					if err != nil {
						log.Printf("error checking compliance for policy [%v] : [%v]\n", policyName, err)
						complianceEvaluation := shared.ComplianceEvaluation{
							AccountId:    accountId,
							ResourceType: shared.AwsIamRole,
							Arn:          *role.Arn,
							ComplianceResult: shared.ComplianceResult{
								Compliance: configServiceTypes.ComplianceTypeNotApplicable,
								Reasons:    nil,
								Message:    "",
							},
							ErrMsg:    err.Error(),
							Timestamp: time.Now(),
						}
						processingErr := ProcessingError{
							ComplianceEvaluation: complianceEvaluation,
							ResultsBuffer:        resultsBuffer,
							Message:              err.Error(),
						}
						HandleError(processingErr, i)
					}
					// send compliance result to results channel
					i.wg.Add(1)
					resultsBuffer <- shared.ComplianceEvaluation{
						AccountId:        accountId,
						Arn:              *role.Arn,
						ComplianceResult: isCompliantResult,
					}
				}
			}
		}
	}
}

func (i *_IAMPolicyEvaluator) processUserCompliance(restrictedActions []string, accountId string, resultsBuffer chan shared.ComplianceEvaluation) {
	defer i.wg.Done()

	// retrieve sdk iam and access analyzer clients
	awscm := i.GetAWSClientMgr()
	client, _ := awscm.GetSDKClient(accountId, awsclientmgr.IAM)
	iamClient := client.(*iam.Client)
	aaClient, _ := awscm.GetSDKClient(accountId, awsclientmgr.AA)
	accessAnalyzerClient := aaClient.(*accessanalyzer.Client)

	// list all policies for users
	listUserPaginator := iam.NewListUsersPaginator(iamClient, &iam.ListUsersInput{})
	for listUserPaginator.HasMorePages() {
		listUserPage, err := listUserPaginator.NextPage(context.Background())
		// check for errors
		if err != nil {
			log.Printf("error retrieving list of users : [%v] \n", err)
			complianceEvaluation := shared.ComplianceEvaluation{
				AccountId:    accountId,
				ResourceType: shared.NotSpecified,
				Arn:          "",
				ComplianceResult: shared.ComplianceResult{
					Compliance: configServiceTypes.ComplianceTypeInsufficientData,
					Reasons:    nil,
					Message:    "",
				},
				ErrMsg:    err.Error(),
				Timestamp: time.Now(),
			}
			processingErr := ProcessingError{
				ComplianceEvaluation: complianceEvaluation,
				ResultsBuffer:        resultsBuffer,
				Message:              err.Error(),
			}
			HandleError(processingErr, i)
			return
		}
		for _, user := range listUserPage.Users {
			log.Printf("processing compliance check for user [%v]\n", *user.UserName)
			// loop through all policies attached to user and retrieve policy document
			listUserPolicyPaginator := iam.NewListUserPoliciesPaginator(iamClient, &iam.ListUserPoliciesInput{
				UserName: user.UserName,
			})
			for listUserPolicyPaginator.HasMorePages() {
				listUserPoliciesPage, err := listUserPolicyPaginator.NextPage(context.Background())
				// check for errors
				if err != nil {
					log.Printf("error retrieving list of policies for user [%v] : [%v]\n", *user.UserName, err)
					complianceEvaluation := shared.ComplianceEvaluation{
						AccountId:    accountId,
						ResourceType: shared.AwsIamUser,
						Arn:          *user.Arn,
						ComplianceResult: shared.ComplianceResult{
							Compliance: configServiceTypes.ComplianceTypeNotApplicable,
							Reasons:    nil,
							Message:    "",
						},
					}
					processingErr := ProcessingError{
						ComplianceEvaluation: complianceEvaluation,
						ResultsBuffer:        resultsBuffer,
						Message:              err.Error(),
					}
					HandleError(processingErr, i)
				}
				for _, policyName := range listUserPoliciesPage.PolicyNames {
					log.Printf("processing compliance check for policy [%v]\n", policyName)
					// retrieve policy document for policy
					getPolicyDocumentOutput, err := iamClient.GetUserPolicy(context.Background(), &iam.GetUserPolicyInput{
						PolicyName: aws.String(policyName),
						UserName:   user.UserName,
					})
					// check for errors
					if err != nil {
						log.Printf("error retrieving policy document for policy [%v] : [%v]\n", policyName, err)
						complianceEvaluation := shared.ComplianceEvaluation{
							AccountId:    accountId,
							ResourceType: shared.AwsIamUser,
							Arn:          *user.Arn,
							ComplianceResult: shared.ComplianceResult{
								Compliance: configServiceTypes.ComplianceTypeNotApplicable,
								Reasons:    nil,
								Message:    "",
							},
							ErrMsg: err.Error(),
						}
						processingErr := ProcessingError{
							ComplianceEvaluation: complianceEvaluation,
							ResultsBuffer:        resultsBuffer,
							Message:              err.Error(),
						}
						HandleError(processingErr, i)
						return
					}
					policyDocument := *getPolicyDocumentOutput.PolicyDocument
					log.Printf("policy name [%v], policy document [%s]\n", policyName, policyDocument)
					// check if policy document is compliant
					isCompliantResult, err := shared.IsCompliant(accessAnalyzerClient, policyDocument, restrictedActions)
					// check for errors
					if err != nil {
						log.Printf("error checking compliance for policy [%v] : [%v]\n", policyName, err)
						complianceEvaluation := shared.ComplianceEvaluation{
							AccountId:    accountId,
							ResourceType: shared.AwsIamUser,
							Arn:          *user.Arn,
							ComplianceResult: shared.ComplianceResult{
								Compliance: configServiceTypes.ComplianceTypeNotApplicable,
								Reasons:    nil,
								Message:    "",
							},
							ErrMsg: err.Error(),
						}
						processingErr := ProcessingError{
							ComplianceEvaluation: complianceEvaluation,
							ResultsBuffer:        resultsBuffer,
							Message:              err.Error(),
						}
						HandleError(processingErr, i)
					}
					// send compliance result to results channel
					i.wg.Add(1)
					resultsBuffer <- shared.ComplianceEvaluation{
						AccountId:        accountId,
						Arn:              *user.Arn,
						ComplianceResult: isCompliantResult,
					}
				}
			}
		}
	}
}

func (i *_IAMPolicyEvaluator) processAllCompliance(restrictedActions []string, accountId string, results chan shared.ComplianceEvaluation) {
	i.wg.Add(1)
	go i.processRoleCompliance(restrictedActions, accountId, results)
	i.wg.Add(1)
	go i.processUserCompliance(restrictedActions, accountId, results)
}

// send evaluation to aws config
func (i *_IAMPolicyEvaluator) SendEvaluations(evaluations []configServiceTypes.Evaluation) {
	// retrieve sdk config client
	accountId := i.accountId
	awscm := i.GetAWSClientMgr()
	client, _ := awscm.GetSDKClient(accountId, awsclientmgr.CONFIG)
	configClient := client.(*configservice.Client)

	// send evaluations to aws config
	_, err := configClient.PutEvaluations(context.Background(), &configservice.PutEvaluationsInput{
		ResultToken: aws.String(i.GetResultToken()),
		Evaluations: evaluations,
		TestMode:    false,
	})
	// check for errors
	if err != nil {
		log.Printf("error sending evaluations to aws config : [%v]\n", err)
	}
}

// check no access
func (i *_IAMPolicyEvaluator) CheckNoAccess(scope string, restrictedActions []string, accountId string, resultsBuffer chan shared.ComplianceEvaluation) error {
	log.Printf("scope=%s, restrictedActions=%v, accountId=%s\n", scope, restrictedActions, accountId)
	switch strings.ToLower(scope) {
	case ROLES:
		{
			i.wg.Add(1)
			go i.processRoleCompliance(restrictedActions, accountId, resultsBuffer)
		}
	case USERS:
		{
			i.wg.Add(1)
			go i.processUserCompliance(restrictedActions, accountId, resultsBuffer)
		}
	case ALL:
		{
			i.processAllCompliance(restrictedActions, accountId, resultsBuffer)
		}
	}
	return nil
}

// ###############################################################################################################
// MANAGING WAIT GROUP METHODS
// ###############################################################################################################

// increment wait group
func (i *_IAMPolicyEvaluator) IncrementWaitGroup(value int) {
	i.wg.Add(value)
}

// decrement wait group
func (i *_IAMPolicyEvaluator) DecrementWaitGroup() {
	i.wg.Done()
}

// wait
func (i *_IAMPolicyEvaluator) Wait() {
	i.wg.Wait()
}

// ###############################################################################################################
// GETTER & SETTER METHODS
// ###############################################################################################################

// get aws client mgr
func (i *_IAMPolicyEvaluator) GetAWSClientMgr() awsclientmgr.AWSClientMgr {
	return i.awsClientMgr
}

// set result token
func (i *_IAMPolicyEvaluator) SetResultToken(token string) {
	i.resultToken = token
}

// get result token
func (i *_IAMPolicyEvaluator) GetResultToken() string {
	return i.resultToken
}

// set scope
func (i *_IAMPolicyEvaluator) SetScope(scope string) {
	i.scope = scope
}

// get scope
func (i *_IAMPolicyEvaluator) GetScope() string {
	return i.scope
}

// set restricted actions
func (i *_IAMPolicyEvaluator) SetRestrictedActions(restrictedActions []string) {
	i.restrictedActions = restrictedActions
}

// get restricted actions
func (i *_IAMPolicyEvaluator) GetRestrictedActions() []string {
	return i.restrictedActions
}

// get entry mgr
func (i *_IAMPolicyEvaluator) GetExporter() exporter.Exporter {
	return i.exporter
}
