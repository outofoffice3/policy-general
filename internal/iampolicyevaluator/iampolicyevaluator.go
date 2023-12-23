package iampolicyevaluator

import (
	"context"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/outofoffice3/policy-general/internal/awsclientmgr"
	"github.com/outofoffice3/policy-general/internal/cache"
	"github.com/outofoffice3/policy-general/internal/errormgr"
	"github.com/outofoffice3/policy-general/internal/evaluationmgr"
	"github.com/outofoffice3/policy-general/internal/metricmgr"
	"github.com/outofoffice3/policy-general/internal/shared"
)

type IAMPolicyEvaluator interface {

	// ###############################################################################################################
	// POLICY EVALUATION METHODS
	// ###############################################################################################################

	// check iam identity policies for restricted actions
	CheckAccessNotGranted(scope string, restrictedActions []string, accountId []string)

	// ###############################################################################################################
	// GETTER METHODS
	// ###############################################################################################################

	// get aws client mgr
	GetAWSClientMgr() awsclientmgr.AWSClientMgr
	// get result token
	GetResultToken() string
	// get scope
	GetScope() string
	// get restricted actions
	GetRestrictedActions() []string
	// get event time
	GetEventTime() time.Time
	// get metric mgr
	GetMetricMgr() metricmgr.MetricMgr
	// get context
	GetContext() context.Context
	// get testmode
	GetTestMode() bool
	// get cache
	GetCache() cache.Cache
}

type _IAMPolicyEvaluator struct {
	ctx               context.Context
	cancelFunc        func()
	resultToken       string
	scope             string
	accountId         string
	restrictedActions []string
	testMode          bool
	eventTime         time.Time
	cache             cache.Cache
	evaluationMgr     evaluationmgr.EvaluationMgr
	errorMgr          errormgr.ErrorMgr
	awsClientMgr      awsclientmgr.AWSClientMgr
	metricMgr         metricmgr.MetricMgr
}

type IAMPolicyEvaluatorInitConfig struct {
	Cfg         aws.Config
	Config      shared.Config
	Ctx         context.Context
	CancelFunc  func()
	ResultToken string
	AccountId   string
}

// returns an instance of iam policy evaluator
func Init(config IAMPolicyEvaluatorInitConfig) IAMPolicyEvaluator {

	// create aws client mgr
	awsClientMgr, err := awsclientmgr.Init(awsclientmgr.AWSClientMgrInitConfig{
		Cfg:       config.Cfg,
		Config:    config.Config,
		AccountId: config.AccountId,
		Ctx:       config.Ctx,
	})
	// return errors
	if err != nil {
		panic("error initializing aws client mgr : " + err.Error())
	}

	mm := metricmgr.Init()

	// convert test mode to bool
	testMode, err := strconv.ParseBool(config.Config.TestMode)
	if err != nil {
		log.Println("error converting testMode string to bool : " + err.Error())
	}

	// create iam policy evaluator
	iamPolicyEvaluator := NewIAMPolicyEvaluator(IAMPolicyEvaluatorInput{
		ctx:        config.Ctx,
		cancelFunc: config.CancelFunc,

		// initialize variables
		accountID:         config.AccountId,
		resultToken:       config.ResultToken,
		restrictedActions: config.Config.RestrictedActions,
		scope:             config.Config.Scope,
		testMode:          config.Config.TestMode,

		// initialize interfaces
		awsClientMgr: awsClientMgr,
		metricMgr:    mm,
		errorMgr:     errormgr.NewErrorMgr(),
		evaluationMgr: evaluationmgr.Init(evaluationmgr.EvaluationMgrInitConfig{
			ResultToken:  config.ResultToken,
			AccountId:    config.AccountId,
			MetricMgr:    mm,
			AwsClientMgr: awsClientMgr,
			TestMode:     testMode,
		}),
	})

	return iamPolicyEvaluator
}

// input to create a new iam policy evaluator
type IAMPolicyEvaluatorInput struct {
	ctx               context.Context
	cancelFunc        func()
	accountID         string
	scope             string
	resultToken       string
	restrictedActions []string
	testMode          string
	awsClientMgr      awsclientmgr.AWSClientMgr
	evaluationMgr     evaluationmgr.EvaluationMgr
	metricMgr         metricmgr.MetricMgr
	errorMgr          errormgr.ErrorMgr
}

// creates a new iam policy evaluator
func NewIAMPolicyEvaluator(input IAMPolicyEvaluatorInput) IAMPolicyEvaluator {

	log.Printf("test mode [%v]\n", input.testMode)
	// convert testMode string to bool
	testMode, err := strconv.ParseBool(input.testMode)
	if err != nil {
		log.Println("error converting testMode string to bool : " + err.Error())
	}
	log.Printf("test mode [%v]\n", testMode)

	iamPolicyEvaluator := &_IAMPolicyEvaluator{
		// set context & cancel function
		ctx:        input.ctx,
		cancelFunc: input.cancelFunc,

		// set variables
		accountId:         input.accountID,
		resultToken:       input.resultToken,
		eventTime:         time.Now().UTC(),
		restrictedActions: input.restrictedActions,
		testMode:          testMode,
		scope:             input.scope,

		// set interfaces
		awsClientMgr:  input.awsClientMgr,
		cache:         cache.NewCache(),
		metricMgr:     input.metricMgr,
		errorMgr:      input.errorMgr,
		evaluationMgr: input.evaluationMgr,
	}
	return iamPolicyEvaluator
}

// ###############################################################################################################
// POLICY EVALUATION METHODS
// ###############################################################################################################

func processAccountRoleCompliance(wg *sync.WaitGroup, restrictedActions []string, accountId string, evalsBuff chan configServiceTypes.Evaluation, iamPolicyEvaluator IAMPolicyEvaluator, errorChan chan<- error) {
	defer wg.Done()

	metricMgr := iamPolicyEvaluator.GetMetricMgr()

	// retrieve sdk iam and access analyzer clients
	awscm := iamPolicyEvaluator.GetAWSClientMgr()
	client, _ := awscm.GetSDKClient(accountId, awsclientmgr.IAM)
	iamClient := client.(*iam.Client)
	aaClient, _ := awscm.GetSDKClient(accountId, awsclientmgr.AA)
	accessAnalyzerClient := aaClient.(*accessanalyzer.Client)

	complianceResultsBuff := make(chan shared.ComplianceResult, 10) // buffer collect managed & inline policy results
	finishSignal := make(chan finishSignal)                         // completion signal for inline policy scan
	defer close(complianceResultsBuff)
	defer close(finishSignal)

	// list all policies for roles
	listRolePaginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{})
	for listRolePaginator.HasMorePages() {
		listRolePage, err := listRolePaginator.NextPage(context.Background())
		// check for errors
		if err != nil {
			log.Printf("error retrieving list of roles : [%v] \n", err)
			errorChan <- errormgr.Error{
				AccountId:          accountId,
				ResourceType:       string(shared.AwsIamRole),
				PolicyDocumentName: "",
				Message:            err.Error(),
				ResourceArn:        "",
			}
			return
		}

		for _, role := range listRolePage.Roles {
			log.Printf("processing role [%v] \n", *role.Arn)
			metricMgr.IncrementMetric(metricmgr.TotalRoles, 1)
			// process role compliance in go routines
			processRoleCompliance(role, iamClient, accessAnalyzerClient, accountId, complianceResultsBuff, evalsBuff, finishSignal, iamPolicyEvaluator, errorChan)
		}
	}

}

type finishSignal struct{}

func processRoleCompliance(role iamTypes.Role, iamClient *iam.Client, accessAnalzyerClient *accessanalyzer.Client, accountId string, complianceResultsBuff chan shared.ComplianceResult, evalsBuff chan configServiceTypes.Evaluation, signal chan finishSignal, iamPolicyEvaluator IAMPolicyEvaluator, errorChan chan<- error) {
	var (
		complianceResults []shared.ComplianceResult
	)

	// process managed policies and inline policies concurrently
	roleWg := &sync.WaitGroup{}
	roleWg.Add(2)
	go processRoleManagedPolicyCompliance(roleWg, role, iamClient, accessAnalzyerClient, accountId, complianceResultsBuff, iamPolicyEvaluator, errorChan)
	go processRoleInlinePolicyCompliance(roleWg, role, iamClient, accessAnalzyerClient, accountId, complianceResultsBuff, iamPolicyEvaluator, errorChan)

	go func() {
		roleWg.Wait()
		log.Printf("role compliance evaluation completed for [%v]\n", *role.Arn)
		signal <- finishSignal{} // send finish signal to terminate for loop
	}()

Loop:
	for {
		select {
		case result, ok := <-complianceResultsBuff:
			{
				if !ok {
					log.Printf("complianceResultsBuff closed for [%v]\n", shared.AwsIamRole)
					return
				}
				// append results from both channels
				complianceResults = append(complianceResults, result)
				log.Printf("compliance results received for [%v] [%v]\n", *role.Arn, result.Compliance)
			}
		case <-signal:
			{
				break Loop
			}
		}
	}

	// create an aws config evaluation from the aggregated compliance results
	awsConfigEvaluation := createAWSConfigEvaluation(shared.AwsIamRole, *role.Arn, iamPolicyEvaluator.GetEventTime(), complianceResults)
	evalsBuff <- awsConfigEvaluation
	log.Printf("evaluated role [%v] as [%v]", *awsConfigEvaluation.ComplianceResourceId, awsConfigEvaluation.ComplianceType)
}

func processAccountUserCompliance(wg *sync.WaitGroup, restrictedActions []string, accountId string, evalsBuff chan configServiceTypes.Evaluation, iamPolicyEvaluator IAMPolicyEvaluator, errorChan chan<- error) {
	defer wg.Done()

	metricMgr := iamPolicyEvaluator.GetMetricMgr()
	// retrieve sdk iam and access analyzer clients
	awscm := iamPolicyEvaluator.GetAWSClientMgr()
	client, _ := awscm.GetSDKClient(accountId, awsclientmgr.IAM)
	iamClient := client.(*iam.Client)
	aaClient, _ := awscm.GetSDKClient(accountId, awsclientmgr.AA)
	accessAnalyzerClient := aaClient.(*accessanalyzer.Client)
	complianceResultsBuff := make(chan shared.ComplianceResult, 10)
	finishSignal := make(chan finishSignal)
	defer close(complianceResultsBuff)
	defer close(finishSignal)

	// list all policies for users
	listUserPaginator := iam.NewListUsersPaginator(iamClient, &iam.ListUsersInput{})
	for listUserPaginator.HasMorePages() {
		listUserPage, err := listUserPaginator.NextPage(context.Background())
		// check for errors
		if err != nil {
			log.Printf("error retrieving list of users : [%v] \n", err)
			errorChan <- errormgr.Error{
				AccountId:          accountId,
				ResourceType:       string(shared.AwsIamUser),
				PolicyDocumentName: "",
				Message:            err.Error(),
				ResourceArn:        "",
			}
			return
		}
		for _, user := range listUserPage.Users {
			metricMgr.IncrementMetric(metricmgr.TotalUsers, 1)
			log.Printf("processing user [%v] \n", *user.Arn)
			processUserCompliance(user, iamClient, accessAnalyzerClient, accountId, complianceResultsBuff, evalsBuff, finishSignal, iamPolicyEvaluator, errorChan)
		}
	}
}

func processUserCompliance(user iamTypes.User, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, complianceResultsBuff chan shared.ComplianceResult, evalsBuff chan configServiceTypes.Evaluation, signal chan finishSignal, iamPolicyEvaluator IAMPolicyEvaluator, errorChan chan<- error) {
	var (
		complianceResults []shared.ComplianceResult
	)

	// process managed policies and inline policies concurrently
	userWg := &sync.WaitGroup{}
	userWg.Add(2)
	go processUserManagedPolicyCompliance(userWg, user, iamClient, accessAnalyzerClient, accountId, complianceResultsBuff, iamPolicyEvaluator, errorChan)
	go processUserInlinePolicyCompliance(userWg, user, iamClient, accessAnalyzerClient, accountId, complianceResultsBuff, iamPolicyEvaluator, errorChan)

	go func() {
		userWg.Wait()
		log.Printf("user compliance evaluation completed for [%v]\n", *user.Arn)
		signal <- finishSignal{} // send finish signal to terminate for loop
	}()

Loop:
	for {
		select {
		case result, ok := <-complianceResultsBuff:
			{
				if !ok {
					log.Printf("compliance results channel closed for [%v]\n", shared.AwsIamUser)
					return
				}
				// append all results from both go routines
				complianceResults = append(complianceResults, result)
				log.Printf("received compliance result for user [%v] : [%+v] \n", *user.Arn, result)
			}
		case <-signal:
			{
				break Loop
			}
		}
	}
	//covert to aws config evaluation and send on evals buffer channel
	awsConfigEvaluation := createAWSConfigEvaluation(shared.AwsIamUser, *user.Arn, iamPolicyEvaluator.GetEventTime(), complianceResults)
	evalsBuff <- awsConfigEvaluation
	log.Printf("evaluated user [%v] as [%v] \n", *user.Arn, awsConfigEvaluation.ComplianceType)
}

func processRoleManagedPolicyCompliance(wg *sync.WaitGroup, role iamTypes.Role, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, complianceResultsBuff chan shared.ComplianceResult, iamPolicyEvaluator IAMPolicyEvaluator, errorChan chan<- error) {
	defer wg.Done()
	metricMgr := iamPolicyEvaluator.GetMetricMgr()
	// loop through all policies attached to role and retrieve policy document
	listAttachedRolePoliciesPaginator := iam.NewListAttachedRolePoliciesPaginator(iamClient, &iam.ListAttachedRolePoliciesInput{
		RoleName: role.RoleName,
	})
	for listAttachedRolePoliciesPaginator.HasMorePages() {
		listAttachedRolePoliciesPage, err := listAttachedRolePoliciesPaginator.NextPage(context.Background())
		// check for errors
		if err != nil {
			metricMgr.IncrementMetric(metricmgr.TotalFailedRolePolicies, 1)
			log.Printf("error retrieving list of policies for role [%v] : [%v] \n ", *role.Arn, err)
			complianceResult := shared.ComplianceResult{
				Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
				Reasons:            nil,
				Message:            err.Error(),
				PolicyDocumentName: "",
				ResourceArn:        *role.Arn,
			}
			complianceResultsBuff <- complianceResult
			errorChan <- errormgr.Error{
				AccountId:          accountId,
				ResourceType:       string(shared.AwsIamRole),
				PolicyDocumentName: "",
				ResourceArn:        *role.Arn,
			}
			return
		}
		// loop through policy documents and check for compliance
		for _, policy := range listAttachedRolePoliciesPage.AttachedPolicies {
			metricMgr.IncrementMetric(metricmgr.TotalRolePolicies, 1)

			// check cache for compliance results first
			cacheComplianceResult, ok := iamPolicyEvaluator.GetCache().Get(cache.CacheKey{
				PK: *policy.PolicyArn,
				SK: accountId,
			})
			if ok {
				complianceResultsBuff <- cacheComplianceResult
				metricMgr.IncrementMetric(metricmgr.TotalCacheHits, 1)
				continue
			}

			// retrieve policy document for policy
			getPolicyOutput, err := iamClient.GetPolicy(context.Background(), &iam.GetPolicyInput{
				PolicyArn: policy.PolicyArn,
			})
			// check for errors
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedRolePolicies, 1)
				log.Printf("error retrieving policy document for policy [%v] : [%v] \n ", *policy.PolicyArn, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: *policy.PolicyName,
					ResourceArn:        *role.Arn,
				}
				complianceResultsBuff <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: *policy.PolicyArn,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				}
				continue
			}
			getPolicyVersionOutput, err := iamClient.GetPolicyVersion(context.Background(), &iam.GetPolicyVersionInput{
				PolicyArn: policy.PolicyArn,
				VersionId: getPolicyOutput.Policy.DefaultVersionId,
			})
			// check for errors
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedRolePolicies, 1)
				log.Printf("error retrieving policy document for policy [%v] : [%v] \n ", *policy.PolicyArn, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: *policy.PolicyName,
					ResourceArn:        *role.Arn,
				}
				complianceResultsBuff <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: *policy.PolicyArn,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				}
				continue
			}
			decodedPolicyDocument, err := url.QueryUnescape(*getPolicyVersionOutput.PolicyVersion.Document)
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedRolePolicies, 1)
				log.Printf("error decoding policy document for policy [%v] : [%v] \n ", *policy.PolicyArn, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: *policy.PolicyName,
					ResourceArn:        *role.Arn,
				}
				complianceResultsBuff <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: *policy.PolicyArn,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				}
				continue
			}
			isCompliantResult, err := IsCompliant(accessAnalyzerClient, decodedPolicyDocument, iamPolicyEvaluator.GetRestrictedActions())
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedRolePolicies, 1)
				log.Printf("error checking compliance for policy [%v] : [%v] \n ", *policy.PolicyArn, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: *policy.PolicyName,
					ResourceArn:        *role.Arn,
				}
				complianceResultsBuff <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: *policy.PolicyArn,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				}
				continue
			}
			complianceResult := shared.ComplianceResult{
				Compliance:         isCompliantResult.Compliance,
				Reasons:            isCompliantResult.Reasons,
				Message:            isCompliantResult.Message,
				PolicyDocumentName: *policy.PolicyName,
				ResourceArn:        *role.Arn,
			}
			complianceResultsBuff <- complianceResult

			// add compliance result to cache
			iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
				PK: *policy.PolicyArn,
				SK: accountId,
			}, complianceResult)
		}
	}
}

func processRoleInlinePolicyCompliance(wg *sync.WaitGroup, role iamTypes.Role, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, complianceResultsBuff chan shared.ComplianceResult, iamPolicyEvaluator IAMPolicyEvaluator, errorChan chan<- error) {
	defer wg.Done()
	metricMgr := iamPolicyEvaluator.GetMetricMgr()
	// loop through all policies attached to role and retrieve policy document
	listRolePolicyPaginator := iam.NewListRolePoliciesPaginator(iamClient, &iam.ListRolePoliciesInput{
		RoleName: role.RoleName,
	})
	for listRolePolicyPaginator.HasMorePages() {
		listRolePoliciesPage, err := listRolePolicyPaginator.NextPage(context.Background())
		// check for errors
		if err != nil {
			metricMgr.IncrementMetric(metricmgr.TotalFailedRolePolicies, 1)
			log.Printf("error retrieving list of policies for role [%v] : [%v] \n ", *role.Arn, err)
			complianceResult := shared.ComplianceResult{
				Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
				Reasons:            nil,
				Message:            err.Error(),
				PolicyDocumentName: "",
				ResourceArn:        *role.Arn,
			}
			complianceResultsBuff <- complianceResult

			// send error to error channel
			errorChan <- errormgr.Error{
				AccountId:          accountId,
				ResourceType:       string(shared.AwsIamRole),
				PolicyDocumentName: "",
				Message:            err.Error(),
				ResourceArn:        *role.Arn,
			}
			return
		}
		// loop through policy documents and check for compliance
		for _, policyName := range listRolePoliciesPage.PolicyNames {
			metricMgr.IncrementMetric(metricmgr.TotalRolePolicies, 1)

			// check cache for compliance results first
			cacheComplianceResult, ok := iamPolicyEvaluator.GetCache().Get(cache.CacheKey{
				PK: policyName,
				SK: accountId,
			})
			if ok {
				complianceResultsBuff <- cacheComplianceResult
				metricMgr.IncrementMetric(metricmgr.TotalCacheHits, 1)
				continue
			}

			// retrieve policy document for policy
			getPolicyDocumentOutput, err := iamClient.GetRolePolicy(context.Background(), &iam.GetRolePolicyInput{
				PolicyName: aws.String(policyName),
				RoleName:   role.RoleName,
			})
			// check for errors
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedRolePolicies, 1)
				log.Printf("error retrieving policy document for policy [%v] : [%v]\n", policyName, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: policyName,
					ResourceArn:        *role.Arn,
				}
				complianceResultsBuff <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: policyName,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: policyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				}
				continue
			}
			policyDocument := *getPolicyDocumentOutput.PolicyDocument
			// check if policy document is compliant
			decodedPolicyDocument, err := url.QueryUnescape(policyDocument)
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedRolePolicies, 1)
				log.Printf("error decoding policy document for policy [%v] : [%v]\n", policyName, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: policyName,
					ResourceArn:        *role.Arn,
				}
				complianceResultsBuff <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: policyName,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: policyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				}
			}
			isCompliantResult, err := IsCompliant(accessAnalyzerClient, decodedPolicyDocument, iamPolicyEvaluator.GetRestrictedActions())
			// check for errors
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedRolePolicies, 1)
				log.Printf("error checking compliance for policy [%v] : [%v]\n", policyName, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: policyName,
					ResourceArn:        *role.Arn,
				}
				complianceResultsBuff <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: policyName,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: policyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				}
				continue
			}
			complianceResult := shared.ComplianceResult{
				Compliance:         isCompliantResult.Compliance,
				Reasons:            isCompliantResult.Reasons,
				Message:            isCompliantResult.Message,
				PolicyDocumentName: policyName,
				ResourceArn:        *role.Arn,
			}
			complianceResultsBuff <- complianceResult

			// add compliance result to cache
			iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
				PK: policyName,
				SK: accountId,
			}, complianceResult)
		}
	}
}

func createAWSConfigEvaluation(resourceType shared.ResourceType, resourceArn string, timeStamp time.Time, complianceResults []shared.ComplianceResult) configServiceTypes.Evaluation {
	// covert to aws config evaluations and send on buffered channel
	var (
		annotations           []string
		currentComplianceType configServiceTypes.ComplianceType
		evaluation            configServiceTypes.Evaluation
	)

	for _, complianceResult := range complianceResults {
		// if empty, set to first compliance type from compliance results
		if currentComplianceType == "" {
			currentComplianceType = complianceResult.Compliance
		}
		switch complianceResult.Compliance {
		case configServiceTypes.ComplianceTypeCompliant:
			{
				continue
			}
		case configServiceTypes.ComplianceTypeNonCompliant:
			{
				//  set compliance type to NON COMPLIANT
				currentComplianceType = configServiceTypes.ComplianceTypeNonCompliant

				// extract reasons from compliance result & add to annotations
				if complianceResult.Reasons != nil {
					reasons := shared.JoinReasons(complianceResult.Reasons, ";")
					block := complianceResult.PolicyDocumentName + " : " + reasons
					annotations = append(annotations, block)
				}
			}
		case configServiceTypes.ComplianceTypeNotApplicable:
			{
				// if current compliance type != not applicable, set compliance type to not applicable
				if currentComplianceType != configServiceTypes.ComplianceTypeNonCompliant {
					currentComplianceType = configServiceTypes.ComplianceTypeNotApplicable
				}

				// extract messages from compliance result & add to annotations
				if complianceResult.Message != "" {
					block := complianceResult.PolicyDocumentName + " : " + complianceResult.Message
					annotations = append(annotations, block)
				}
			}
		default:
			{
				log.Printf("default case : [%v]\n", currentComplianceType)
			}
		}
	}

	// create aws config evaluation
	evaluation = configServiceTypes.Evaluation{
		ComplianceResourceId:   aws.String(resourceArn),
		ComplianceResourceType: aws.String(string(resourceType)),
		ComplianceType:         currentComplianceType,
		Annotation:             aws.String(strings.Join(annotations, "\n")),
		OrderingTimestamp:      aws.Time(timeStamp),
	}
	return evaluation
}

func processUserManagedPolicyCompliance(wg *sync.WaitGroup, user iamTypes.User, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, complianceResultsBuff chan shared.ComplianceResult, iamPolicyEvaluator IAMPolicyEvaluator, errorChan chan<- error) {
	defer wg.Done()
	metricMgr := iamPolicyEvaluator.GetMetricMgr()
	// loop through all policies attached to role and retrieve policy document
	listAttachedUserPoliciesPaginator := iam.NewListAttachedUserPoliciesPaginator(iamClient, &iam.ListAttachedUserPoliciesInput{
		UserName: user.UserName,
	})
	for listAttachedUserPoliciesPaginator.HasMorePages() {
		listUserPoliciesPage, err := listAttachedUserPoliciesPaginator.NextPage(context.Background())
		// check for errors
		if err != nil {
			metricMgr.IncrementMetric(metricmgr.TotalFailedUserPolicies, 1)
			log.Printf("error retrieving list of policies for user [%v] : [%v] \n ", *user.UserName, err)
			complianceResult := shared.ComplianceResult{
				Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
				Reasons:            nil,
				Message:            err.Error(),
				PolicyDocumentName: "",
				ResourceArn:        *user.Arn,
			}
			complianceResultsBuff <- complianceResult

			// send error to channnel to error
			errorChan <- errormgr.Error{
				AccountId:          accountId,
				ResourceType:       string(shared.AwsIamUser),
				PolicyDocumentName: "",
				Message:            err.Error(),
				ResourceArn:        *user.Arn,
			}
			return
		}
		// loop through policies attached to user
		for _, policy := range listUserPoliciesPage.AttachedPolicies {
			metricMgr.IncrementMetric(metricmgr.TotalUserPolicies, 1)

			// check cache for compliance results first
			cacheComplianceResult, ok := iamPolicyEvaluator.GetCache().Get(cache.CacheKey{
				PK: *policy.PolicyArn,
				SK: accountId,
			})
			if ok {
				complianceResultsBuff <- cacheComplianceResult
				metricMgr.IncrementMetric(metricmgr.TotalCacheHits, 1)
				continue
			}

			// retrieve policy document
			getPolicyOutput, err := iamClient.GetPolicy(context.Background(), &iam.GetPolicyInput{
				PolicyArn: policy.PolicyArn,
			})
			// check for errors
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedUserPolicies, 1)
				log.Printf("error retrieving policy document for policy [%v] : [%v]\n", *policy.PolicyArn, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: *policy.PolicyName,
					ResourceArn:        *user.Arn,
				}
				complianceResultsBuff <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: *policy.PolicyArn,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				}
				continue
			}
			getPolicyVersionOutput, err := iamClient.GetPolicyVersion(context.Background(), &iam.GetPolicyVersionInput{
				PolicyArn: policy.PolicyArn,
				VersionId: getPolicyOutput.Policy.DefaultVersionId,
			})
			// check for errors
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedUserPolicies, 1)
				log.Printf("error retrieving policy document for policy [%v] : [%v]\n", *policy.PolicyArn, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: *policy.PolicyName,
					ResourceArn:        *user.Arn,
				}
				complianceResultsBuff <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: *policy.PolicyArn,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				}
				continue
			}
			decodedPolicyDocument, err := url.QueryUnescape(*getPolicyVersionOutput.PolicyVersion.Document)
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedUserPolicies, 1)
				log.Printf("error decoding policy document for policy [%v] : [%v]\n", *policy.PolicyArn, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: *policy.PolicyName,
					ResourceArn:        *user.Arn,
				}
				complianceResultsBuff <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: *policy.PolicyArn,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				}
				continue
			}
			isCompliantResult, err := IsCompliant(accessAnalyzerClient, decodedPolicyDocument, iamPolicyEvaluator.GetRestrictedActions())
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedUserPolicies, 1)
				log.Printf("error checking compliance for policy [%v] : [%v]\n", *policy.PolicyArn, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: *policy.PolicyName,
					ResourceArn:        *user.Arn,
				}
				complianceResultsBuff <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: *policy.PolicyArn,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				}
				continue
			}
			complianceResult := shared.ComplianceResult{
				Compliance:         isCompliantResult.Compliance,
				Reasons:            isCompliantResult.Reasons,
				Message:            isCompliantResult.Message,
				PolicyDocumentName: *policy.PolicyName,
				ResourceArn:        *user.Arn,
			}
			complianceResultsBuff <- complianceResult

			// add compliance result to cache
			iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
				PK: *policy.PolicyArn,
				SK: accountId,
			}, complianceResult)
		}
	}
}

func processUserInlinePolicyCompliance(wg *sync.WaitGroup, user iamTypes.User, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, resultsBuffer chan shared.ComplianceResult, iamPolicyEvaluator IAMPolicyEvaluator, errorChan chan<- error) {
	defer wg.Done()
	metricMgr := iamPolicyEvaluator.GetMetricMgr()
	// loop through all policies attached to role and retrieve policy document
	listUserPolicyPaginator := iam.NewListUserPoliciesPaginator(iamClient, &iam.ListUserPoliciesInput{
		UserName: user.UserName,
	})
	for listUserPolicyPaginator.HasMorePages() {
		listUserPoliciesPage, err := listUserPolicyPaginator.NextPage(context.Background())
		// check for errors
		if err != nil {
			metricMgr.IncrementMetric(metricmgr.TotalFailedUserPolicies, 1)
			log.Printf("error retrieving list of policies for user [%v] : [%v] \n ", *user.UserName, err)
			complianceResult := shared.ComplianceResult{
				Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
				Reasons:            nil,
				Message:            err.Error(),
				PolicyDocumentName: "",
				ResourceArn:        *user.Arn,
			}
			resultsBuffer <- complianceResult
			errorChan <- errormgr.Error{
				AccountId:          accountId,
				ResourceType:       string(shared.AwsIamUser),
				PolicyDocumentName: "",
				Message:            err.Error(),
				ResourceArn:        *user.Arn,
			}
			return
		}
		// loop through policy documents and check for compliance
		for _, policyName := range listUserPoliciesPage.PolicyNames {

			// check cache for compliance results first
			cacheComplianceResult, ok := iamPolicyEvaluator.GetCache().Get(cache.CacheKey{
				PK: policyName,
				SK: accountId,
			})
			if ok {
				resultsBuffer <- cacheComplianceResult
				metricMgr.IncrementMetric(metricmgr.TotalCacheHits, 1)
				continue
			}

			metricMgr.IncrementMetric(metricmgr.TotalUserPolicies, 1)
			// retrieve policy document for policy
			getPolicyDocumentOutput, err := iamClient.GetUserPolicy(context.Background(), &iam.GetUserPolicyInput{
				PolicyName: aws.String(policyName),
				UserName:   user.UserName,
			})
			// check for errors
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedUserPolicies, 1)
				log.Printf("error retrieving policy document for policy [%v] : [%v]\n", policyName, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: policyName,
					ResourceArn:        *user.Arn,
				}
				resultsBuffer <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: policyName,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: policyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				}
				continue
			}
			policyDocument := *getPolicyDocumentOutput.PolicyDocument
			// check if policy document is compliantcompliance result added to batch
			decodedPolicyDocument, err := url.QueryUnescape(policyDocument)
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedUserPolicies, 1)
				log.Printf("error decoding policy document for policy [%v] : [%v]\n", policyName, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: policyName,
					ResourceArn:        *user.Arn,
				}
				resultsBuffer <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: policyName,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: policyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				}
				continue
			}
			isCompliantResult, err := IsCompliant(accessAnalyzerClient, decodedPolicyDocument, iamPolicyEvaluator.GetRestrictedActions())
			// check for errors
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedUserPolicies, 1)
				log.Printf("error checking compliance for policy [%v] : [%v]\n", policyName, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: policyName,
					ResourceArn:        *user.Arn,
				}
				resultsBuffer <- complianceResult

				// add compliance result to cache
				iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
					PK: policyName,
					SK: accountId,
				}, complianceResult)

				// send error to error channel
				errorChan <- errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: policyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				}
				continue
			}
			complianceResult := shared.ComplianceResult{
				Compliance:         isCompliantResult.Compliance,
				Reasons:            isCompliantResult.Reasons,
				Message:            isCompliantResult.Message,
				PolicyDocumentName: policyName,
				ResourceArn:        *user.Arn,
			}
			resultsBuffer <- complianceResult

			// add compliance result to cache
			iamPolicyEvaluator.GetCache().Set(cache.CacheKey{
				PK: policyName,
				SK: accountId,
			}, complianceResult)
		}
	}
}

// check for restricted actions
func (i *_IAMPolicyEvaluator) CheckAccessNotGranted(scope string, restrictedActions []string, accountIds []string) {
	prefix := time.Now().Format(time.RFC3339) // create prefix for files written to s3

	// create error buffer for go routines
	errorBuff := make(chan error, 10)
	errorWg := &sync.WaitGroup{}
	errorWg.Add(1)

	// process errors as they come into buffer
	go func() {
		defer errorWg.Done()
		i.errorMgr.ListenForErrors(errorBuff)
	}()

	// create buffer for aws config evaluations
	evalsBuff := make(chan configServiceTypes.Evaluation, 125)
	evalWg := &sync.WaitGroup{}
	evalWg.Add(1)

	// process aws config evaluations as they come into buffer
	go func() {
		defer evalWg.Done()
		i.evaluationMgr.ListenForEvaluations(evalsBuff, errorBuff)
	}()

	accountWg := &sync.WaitGroup{}
	for _, accountId := range accountIds {
		// process each account in a go routine
		accountWg.Add(1)
		go func(accountId string) {
			defer accountWg.Done()
			switch strings.ToLower(scope) {
			case ROLES:
				{
					roleWg := &sync.WaitGroup{}
					roleWg.Add(1)
					go processAccountRoleCompliance(roleWg, restrictedActions, accountId, evalsBuff, i, errorBuff)
					roleWg.Wait()
				}
			case USERS:
				{
					userWg := &sync.WaitGroup{}
					userWg.Add(1)
					go processAccountUserCompliance(userWg, restrictedActions, accountId, evalsBuff, i, errorBuff)
					userWg.Wait()
				}
			case ALL:
				{
					roleWg := &sync.WaitGroup{}
					roleWg.Add(1)
					go processAccountRoleCompliance(roleWg, restrictedActions, accountId, evalsBuff, i, errorBuff)

					userWg := &sync.WaitGroup{}
					userWg.Add(1)
					go processAccountUserCompliance(userWg, restrictedActions, accountId, evalsBuff, i, errorBuff)
					userWg.Wait()
					roleWg.Wait()
				}
			}
		}(accountId)
	}
	accountWg.Wait() // wait for all accounts to complete processing
	close(evalsBuff) // close aws config evaluations buffer
	evalWg.Wait()    // wait for aws config evaluations to be sent to aws config

	evalMgrCSVWg := &sync.WaitGroup{}
	// write evaluations to csv file
	evalMgrCSVWg.Add(1)
	go func() {
		defer evalMgrCSVWg.Done()
		var (
			filename string
			header   []string
			records  [][]string
		)
		filename = string(shared.ExecutionLogFileName)
		header = []string{"ResourceId", "ResourceType", "ComplianceType", "Annotation", "OrderingTimestamp"}
		items := i.evaluationMgr.GetEvaluations()
		// covert items to [][]string to be a csv file
		for _, evaluation := range items {
			records = append(records, []string{
				*evaluation.ComplianceResourceId,
				*evaluation.ComplianceResourceType,
				string(evaluation.ComplianceType),
				*evaluation.Annotation,
				evaluation.OrderingTimestamp.Format(time.RFC3339),
			})
		}
		i.evaluationMgr.WriteCSV(filename, header, records, i.evaluationMgr.GetWriter(), errorBuff)
	}()

	evalMgrS3Wg := new(sync.WaitGroup)
	evalMgrS3Wg.Add(1)
	go func() {
		defer evalMgrS3Wg.Done()
		evalMgrCSVWg.Wait() // wait for csv file to be written
		// convert file to byte stream
		file, err := os.ReadFile(string(shared.ExecutionLogFileName))
		// send errors to error channel
		if err != nil {
			errorBuff <- err
		}
		// write evaluations to s3
		i.evaluationMgr.ExportToS3(
			string(shared.ConfigFileBucketName),
			string(shared.CheckAccessNotGrantedConfigFileObjKey),
			prefix,
			file,
			i.evaluationMgr.GetWriter(),
			errorBuff,
		)
	}()

	evalMgrS3Wg.Wait() // wait for file to be written to s3
	close(errorBuff)   // close error buffer
	errorWg.Wait()     // wait for errors to be sent to error manager
}

// ###############################################################################################################
// GETTER & SETTER METHODS
// ###############################################################################################################

// get cache
func (i *_IAMPolicyEvaluator) GetCache() cache.Cache {
	return i.cache
}

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

// get event time
func (i *_IAMPolicyEvaluator) GetEventTime() time.Time {
	return i.eventTime
}

// get metric mgr
func (i *_IAMPolicyEvaluator) GetMetricMgr() metricmgr.MetricMgr {
	return i.metricMgr
}

// get context
func (i *_IAMPolicyEvaluator) GetContext() context.Context {
	return i.ctx
}

// get test mode
func (i *_IAMPolicyEvaluator) GetTestMode() bool {
	return i.testMode
}

func IsCompliant(client *accessanalyzer.Client, policyDocument string, restrictedActions []string) (shared.ComplianceResult, error) {
	input := accessanalyzer.CheckAccessNotGrantedInput{
		Access: []accessAnalyzerTypes.Access{
			{
				Actions: restrictedActions,
			},
		},
		PolicyDocument: aws.String(policyDocument),
		PolicyType:     accessAnalyzerTypes.AccessCheckPolicyTypeIdentityPolicy,
	}
	output, err := client.CheckAccessNotGranted(context.Background(), &input)
	// return errors
	if err != nil {
		return shared.ComplianceResult{}, err
	}
	// check if policy is compliant
	if output.Result == accessAnalyzerTypes.CheckAccessNotGrantedResultPass {
		return shared.ComplianceResult{
			Compliance: configServiceTypes.ComplianceTypeCompliant,
			Reasons:    output.Reasons,
			Message:    *output.Message,
		}, nil
	}
	return shared.ComplianceResult{
		Compliance: configServiceTypes.ComplianceTypeNonCompliant,
		Reasons:    output.Reasons,
		Message:    *output.Message,
	}, nil
}
