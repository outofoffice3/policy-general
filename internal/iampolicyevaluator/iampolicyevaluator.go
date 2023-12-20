package iampolicyevaluator

import (
	"context"
	"log"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/outofoffice3/policy-general/internal/awsclientmgr"
	"github.com/outofoffice3/policy-general/internal/entrymgr"
	"github.com/outofoffice3/policy-general/internal/errormgr"
	"github.com/outofoffice3/policy-general/internal/exporter"
	"github.com/outofoffice3/policy-general/internal/gotracker"
	"github.com/outofoffice3/policy-general/internal/metricmgr"
	"github.com/outofoffice3/policy-general/internal/shared"
)

type IAMPolicyEvaluator interface {

	// ###############################################################################################################
	// POLICY EVALUATION METHODS
	// ###############################################################################################################

	// check iam identity policies for restricted actions
	CheckAccessNotGranted(scope string, restrictedActions []string, accountId []string)

	// add error
	AddError(err error)

	// ###############################################################################################################
	// GETTER METHODS
	// ###############################################################################################################

	// get aws client mgr
	GetAWSClientMgr() awsclientmgr.AWSClientMgr
	// get exporter
	GetExporter() exporter.Exporter
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
	// get go tracker
	GetGoTracker() gotracker.GoroutineTracker
	// get context
	GetContext() context.Context
	// get testmode
	GetTestMode() bool
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
	errorMgr          errormgr.ErrorMgr
	awsClientMgr      awsclientmgr.AWSClientMgr
	exporter          exporter.Exporter
	metricMgr         metricmgr.MetricMgr
	goTracker         gotracker.GoroutineTracker
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
	// create entry mgr
	entryMgr := entrymgr.Init()

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

	// creeate exporter
	exporter, err := exporter.Init(exporter.ExporterInitConfig{
		AwsClientMgr: awsClientMgr,
		EntryMgr:     entryMgr,
		AccountId:    config.AccountId,
	})
	// return errors
	if err != nil {
		panic("error initializing exporter : " + err.Error())

	}

	mm := metricmgr.Init()

	gt := gotracker.NewTracker()

	errorMgr := errormgr.New(errormgr.NewErrorMgrInput{
		AwsClientMgr: awsClientMgr,
		AccountId:    config.AccountId,
	})

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
		exporter:     exporter,
		awsClientMgr: awsClientMgr,
		metricMgr:    mm,
		goTracker:    gt,
		errorMgr:     errorMgr,
	})

	return iamPolicyEvaluator
}

// input to create a new iam policy evaluator
type IAMPolicyEvaluatorInput struct {
	ctx               context.Context
	cancelFunc        func()
	awsClientMgr      awsclientmgr.AWSClientMgr
	exporter          exporter.Exporter
	accountID         string
	scope             string
	resultToken       string
	restrictedActions []string
	testMode          string
	metricMgr         metricmgr.MetricMgr
	goTracker         gotracker.GoroutineTracker
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
		// set context
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
		awsClientMgr: input.awsClientMgr,
		exporter:     input.exporter,
		metricMgr:    input.metricMgr,
		goTracker:    input.goTracker,
		errorMgr:     input.errorMgr,
	}

	return iamPolicyEvaluator
}

// ###############################################################################################################
// POLICY EVALUATION METHODS
// ###############################################################################################################

func processAccountRoleCompliance(wg *sync.WaitGroup, restrictedActions []string, accountId string, evalsBuff chan configServiceTypes.Evaluation, iamPolicyEvaluator IAMPolicyEvaluator) {
	gt := iamPolicyEvaluator.GetGoTracker()
	gt.TrackDeferCall("processAccountRoleCompliance", restrictedActions, accountId)
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
			iamPolicyEvaluator.AddError(errormgr.Error{
				AccountId:          accountId,
				ResourceType:       string(shared.AwsIamRole),
				PolicyDocumentName: "",
				Message:            err.Error(),
				ResourceArn:        "",
			})
			return
		}
		for _, role := range listRolePage.Roles {
			log.Printf("processing role [%v] \n", *role.Arn)
			metricMgr.IncrementMetric(metricmgr.TotalRoles, 1)
			processRoleCompliance(role, iamClient, accessAnalyzerClient, accountId, complianceResultsBuff, evalsBuff, finishSignal, iamPolicyEvaluator)
		}
	}
}

type finishSignal struct{}

func processRoleCompliance(role types.Role, iamClient *iam.Client, accessAnalzyerClient *accessanalyzer.Client, accountId string, complianceResultsBuff chan shared.ComplianceResult, evalsBuff chan configServiceTypes.Evaluation, signal chan finishSignal, iamPolicyEvaluator IAMPolicyEvaluator) {
	gt := iamPolicyEvaluator.GetGoTracker()
	var (
		complianceResults []shared.ComplianceResult
	)

	// process managed policies and inline policies concurrently
	roleWg := &sync.WaitGroup{}
	roleWg.Add(2)
	gt.TrackGoroutine("processRoleManagedPolicyCompliance", *role.Arn, accountId)
	go processRoleManagedPolicyCompliance(roleWg, role, iamClient, accessAnalzyerClient, accountId, complianceResultsBuff, iamPolicyEvaluator)
	gt.TrackGoroutine("processRoleInlinePolicyCompliance", *role.Arn, accountId)
	go processRoleInlinePolicyCompliance(roleWg, role, iamClient, accessAnalzyerClient, accountId, complianceResultsBuff, iamPolicyEvaluator)

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

func processAccountUserCompliance(wg *sync.WaitGroup, restrictedActions []string, accountId string, evalsBuff chan configServiceTypes.Evaluation, iamPolicyEvaluator IAMPolicyEvaluator) {
	gt := iamPolicyEvaluator.GetGoTracker()
	gt.TrackDeferCall("processAccountUserCompliance", restrictedActions, accountId)
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
			iamPolicyEvaluator.AddError(errormgr.Error{
				AccountId:          accountId,
				ResourceType:       string(shared.AwsIamUser),
				PolicyDocumentName: "",
				Message:            err.Error(),
				ResourceArn:        "",
			})
			return
		}
		for _, user := range listUserPage.Users {
			metricMgr.IncrementMetric(metricmgr.TotalUsers, 1)
			log.Printf("processing user [%v] \n", *user.Arn)
			processUserCompliance(user, iamClient, accessAnalyzerClient, accountId, complianceResultsBuff, evalsBuff, finishSignal, iamPolicyEvaluator)
		}
	}
}

func processUserCompliance(user types.User, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, complianceResultsBuff chan shared.ComplianceResult, evalsBuff chan configServiceTypes.Evaluation, signal chan finishSignal, iamPolicyEvaluator IAMPolicyEvaluator) {
	gt := iamPolicyEvaluator.GetGoTracker()
	var (
		complianceResults []shared.ComplianceResult
	)

	// process managed policies and inline policies concurrently
	userWg := &sync.WaitGroup{}
	userWg.Add(2)
	gt.TrackGoroutine("processUserManagedPolicyCompliance", *user.Arn, accountId)
	go processUserManagedPolicyCompliance(userWg, user, iamClient, accessAnalyzerClient, accountId, complianceResultsBuff, iamPolicyEvaluator)
	gt.TrackGoroutine("processUserInlinePolicyCompliance", *user.Arn, accountId)
	go processUserInlinePolicyCompliance(userWg, user, iamClient, accessAnalyzerClient, accountId, complianceResultsBuff, iamPolicyEvaluator)

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

func processRoleManagedPolicyCompliance(wg *sync.WaitGroup, role types.Role, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, complianceResultsBuff chan shared.ComplianceResult, iamPolicyEvaluator IAMPolicyEvaluator) {
	gt := iamPolicyEvaluator.GetGoTracker()
	gt.TrackDeferCall("processRoleManagedPolicyCompliance", *role.Arn, accountId)
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
			iamPolicyEvaluator.AddError(errormgr.Error{
				AccountId:          accountId,
				ResourceType:       string(shared.AwsIamRole),
				PolicyDocumentName: "",
				ResourceArn:        *role.Arn,
			})
			return
		}
		// loop through policy documents and check for compliance
		for _, policy := range listAttachedRolePoliciesPage.AttachedPolicies {
			metricMgr.IncrementMetric(metricmgr.TotalRolePolicies, 1)
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				})
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				})
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				})
				continue
			}
			isCompliantResult, err := shared.IsCompliant(accessAnalyzerClient, decodedPolicyDocument, iamPolicyEvaluator.GetRestrictedActions())
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				})
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
		}
	}
}

func processRoleInlinePolicyCompliance(wg *sync.WaitGroup, role types.Role, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, complianceResultsBuff chan shared.ComplianceResult, iamPolicyEvaluator IAMPolicyEvaluator) {
	gt := iamPolicyEvaluator.GetGoTracker()
	gt.TrackDeferCall("processRoleInlinePolicyCompliance", *role.Arn, accountId)
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
			iamPolicyEvaluator.AddError(errormgr.Error{
				AccountId:          accountId,
				ResourceType:       string(shared.AwsIamRole),
				PolicyDocumentName: "",
				Message:            err.Error(),
				ResourceArn:        *role.Arn,
			})
			return
		}
		// loop through policy documents and check for compliance
		for _, policyName := range listRolePoliciesPage.PolicyNames {
			metricMgr.IncrementMetric(metricmgr.TotalRolePolicies, 1)
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: policyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				})
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: policyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				})
			}
			isCompliantResult, err := shared.IsCompliant(accessAnalyzerClient, decodedPolicyDocument, iamPolicyEvaluator.GetRestrictedActions())
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamRole),
					PolicyDocumentName: policyName,
					Message:            err.Error(),
					ResourceArn:        *role.Arn,
				})
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

func processUserManagedPolicyCompliance(wg *sync.WaitGroup, user types.User, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, complianceResultsBuff chan shared.ComplianceResult, iamPolicyEvaluator IAMPolicyEvaluator) {
	gt := iamPolicyEvaluator.GetGoTracker()
	gt.TrackDeferCall("processUserManagedPolicyCompliance", *user.Arn, accountId)
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
			iamPolicyEvaluator.AddError(errormgr.Error{
				AccountId:          accountId,
				ResourceType:       string(shared.AwsIamUser),
				PolicyDocumentName: "",
				Message:            err.Error(),
				ResourceArn:        *user.Arn,
			})
			return
		}
		// loop through policies attached to user
		for _, policy := range listUserPoliciesPage.AttachedPolicies {
			metricMgr.IncrementMetric(metricmgr.TotalUserPolicies, 1)
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				})
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				})
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				})
				continue
			}
			isCompliantResult, err := shared.IsCompliant(accessAnalyzerClient, decodedPolicyDocument, iamPolicyEvaluator.GetRestrictedActions())
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: *policy.PolicyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				})
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
		}
	}
}

func processUserInlinePolicyCompliance(wg *sync.WaitGroup, user types.User, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, resultsBuffer chan shared.ComplianceResult, iamPolicyEvaluator IAMPolicyEvaluator) {
	gt := iamPolicyEvaluator.GetGoTracker()
	gt.TrackDeferCall("processUserInlinePolicyCompliance", *user.Arn, accountId)
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
			iamPolicyEvaluator.AddError(errormgr.Error{
				AccountId:          accountId,
				ResourceType:       string(shared.AwsIamUser),
				PolicyDocumentName: "",
				Message:            err.Error(),
				ResourceArn:        *user.Arn,
			})
			return
		}
		// loop through policy documents and check for compliance
		for _, policyName := range listUserPoliciesPage.PolicyNames {
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: policyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				})
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: policyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				})
				continue
			}
			isCompliantResult, err := shared.IsCompliant(accessAnalyzerClient, decodedPolicyDocument, iamPolicyEvaluator.GetRestrictedActions())
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
				iamPolicyEvaluator.AddError(errormgr.Error{
					AccountId:          accountId,
					ResourceType:       string(shared.AwsIamUser),
					PolicyDocumentName: policyName,
					Message:            err.Error(),
					ResourceArn:        *user.Arn,
				})
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
		}
	}
}

// send evaluation to aws config
func (i *_IAMPolicyEvaluator) sendEvaluations(evalWrapper [100]shared.ConfigEval, testMode bool) error {
	log.Printf("test mode : [%v]\n", testMode)
	metricMgr := i.GetMetricMgr()
	// retrieve sdk config client
	accountId := i.accountId
	awscm := i.GetAWSClientMgr()
	client, _ := awscm.GetSDKClient(accountId, awsclientmgr.CONFIG)
	configClient := client.(*configservice.Client)

	// append config evaluations from eval wrapper
	var evaluations []configServiceTypes.Evaluation
	for _, eval := range evalWrapper {
		if eval.Empty {
			log.Println("skipping empty eval")
			continue
		}
		log.Println("appended eval to slice")
		evaluations = append(evaluations, eval.Eval)
	}

	// send evaluations to aws config
	_, err := configClient.PutEvaluations(context.Background(), &configservice.PutEvaluationsInput{
		ResultToken: aws.String(i.GetResultToken()),
		Evaluations: evaluations,
		TestMode:    testMode,
	})
	// check for errors
	if err != nil {
		metricMgr.IncrementMetric(metricmgr.TotalFailedEvaluations, 1)
		log.Printf("error sending evaluations to aws config : [%v]\n", err)
		configErr := errormgr.Error{
			AccountId:          accountId,
			Message:            err.Error(),
			ResourceType:       "",
			PolicyDocumentName: "",
			ResourceArn:        "",
		}
		i.AddError(configErr)
		return configErr
	}
	metricMgr.IncrementMetric(metricmgr.TotalEvaluations, int32(len(evaluations)))
	return nil
}

// check for restricted actions
func (i *_IAMPolicyEvaluator) CheckAccessNotGranted(scope string, restrictedActions []string, accountIds []string) {
	gt := i.GetGoTracker()
	mm := i.GetMetricMgr()
	prefix := time.Now().Format(time.RFC3339) // create prefix for files written to s3

	// create buffer for aws config evaluations
	evalsBuff := make(chan configServiceTypes.Evaluation, 105)
	evalWg := &sync.WaitGroup{}
	evalWg.Add(1)

	// process aws config evaluations as they come into buffer
	go func() {
		defer evalWg.Done()
		maxBatchCount := int32(100)
		var (
			batchEvaluations [100]shared.ConfigEval
			index            int32
			currentIndex     int32
			empty            bool
		)

		for evaluation := range evalsBuff {
			{
				i.exporter.AddEntry(evaluation)
				empty = false
				validAnnotation := shared.ValidateAnnotation(*evaluation.Annotation, 250)
				evaluation.Annotation = aws.String(validAnnotation)
				log.Printf("evaluation received for [%v]\n", *evaluation.ComplianceResourceId)
				index = atomic.AddInt32(&index, 1) - 1 // set index
				batchEvaluations[index] = shared.ConfigEval{
					Empty: false,
					Eval:  evaluation,
				}
				mm.IncrementMetric(metricmgr.TotalEvaluations, 1) // increment total evaluations counter

				currentIndex = atomic.LoadInt32(&index)
				if currentIndex == (maxBatchCount - int32(1)) {
					err := i.sendEvaluations(batchEvaluations, i.GetTestMode())
					if err != nil {
						log.Printf("error sending evaluations to aws config: [%v]\n", err)
					}
					// reset index to 0
					atomic.StoreInt32(&index, 0)
					empty = true
					// clear out array
					for i := 0; i < len(batchEvaluations); i++ {
						batchEvaluations[i] = shared.ConfigEval{
							Empty: true,
							Eval:  configServiceTypes.Evaluation{},
						}
					}
					totalEvaluations, _ := mm.GetMetric(metricmgr.TotalEvaluations)
					log.Printf("sent [%v] evaluations to aws config\n", totalEvaluations)
				}
			}
		}
		if empty {
			// send remaining evaluations
			err := i.sendEvaluations(batchEvaluations, i.GetTestMode())
			if err != nil {
				log.Printf("error sending evaluations to aws config: [%v]\n", err)
			}
			log.Println("sent remaining  evaluations to aws config")
		}
		totalEvaluations, _ := mm.GetMetric(metricmgr.TotalEvaluations)
		log.Printf("Exiting AWS config evals go routine after sending [%v] total evaluations", totalEvaluations)
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
					go processAccountRoleCompliance(roleWg, restrictedActions, accountId, evalsBuff, i)
					gt.TrackGoroutine("processAccountRoleCompliance", restrictedActions, accountId)
					roleWg.Wait()
				}
			case USERS:
				{
					userWg := &sync.WaitGroup{}
					userWg.Add(1)
					go processAccountUserCompliance(userWg, restrictedActions, accountId, evalsBuff, i)
					gt.TrackGoroutine("processAccountUserCompliance", restrictedActions, accountId)
					userWg.Wait()
				}
			case ALL:
				{
					roleWg := &sync.WaitGroup{}
					roleWg.Add(1)
					go processAccountRoleCompliance(roleWg, restrictedActions, accountId, evalsBuff, i)
					gt.TrackGoroutine("processAccountRoleCompliance", restrictedActions, accountId)

					userWg := &sync.WaitGroup{}
					userWg.Add(1)
					go processAccountUserCompliance(userWg, restrictedActions, accountId, evalsBuff, i)
					gt.TrackGoroutine("processAccountUserCompliance", restrictedActions, accountId)
					userWg.Wait()
					roleWg.Wait()
				}
			}
		}(accountId)
	}
	accountWg.Wait() // wait for all accounts to complete processing
	close(evalsBuff) // close aws config evaluations buffer
	evalWg.Wait()    // wait for aws config evaluatoins to be sent to aws config

	errorWg := &sync.WaitGroup{}
	errorWg.Add(1)

	go func() {
		defer errorWg.Done()
		err := i.errorMgr.WriteToCSV(string(shared.ErrorLogFileObjectKey))
		if err != nil {
			log.Printf("error writing error log to csv : [%v]\n", err)
		}
		log.Println("error log file written to csv")
	}()

	exportsWg := &sync.WaitGroup{}
	exportsWg.Add(1)
	go func() {
		defer exportsWg.Done()
		errorWg.Wait()
		key, err := i.errorMgr.ExportToS3(string(shared.ConfigFileBucketName), string(shared.ErrorLogFileObjectKey), prefix)
		if err != nil {
			log.Printf("error writing error log to s3 : [%v]\n", err)
		}
		log.Printf("error log file written to s3 [%v]\n", key)
	}()

	executionLogWg := &sync.WaitGroup{}
	executionLogWg.Add(1)

	go func() {
		defer executionLogWg.Done()
		err := i.exporter.WriteToCSV(string(shared.ExecutionLogFileName))
		if err != nil {
			log.Printf("error writing config evaluations to csv : [%v]\n", err)
		}
		log.Println("config evaluations written to csv")
	}()

	exportsWg.Add(1)
	go func() {
		defer exportsWg.Done()
		executionLogWg.Wait()
		key, err := i.exporter.ExportToS3(string(shared.ConfigFileBucketName), string(shared.ExecutionLogFileName), prefix)
		if err != nil {
			log.Printf("error writing config evaluations to s3 : [%v]\n", err)
		}
		log.Printf("config evaluations written to s3 [%v]\n", key)
	}()

	exportsWg.Wait()
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

// get event time
func (i *_IAMPolicyEvaluator) GetEventTime() time.Time {
	return i.eventTime
}

// get metric mgr
func (i *_IAMPolicyEvaluator) GetMetricMgr() metricmgr.MetricMgr {
	return i.metricMgr
}

// get go tracker
func (i *_IAMPolicyEvaluator) GetGoTracker() gotracker.GoroutineTracker {
	return i.goTracker
}

// get context
func (i *_IAMPolicyEvaluator) GetContext() context.Context {
	return i.ctx
}

// get test mode
func (i *_IAMPolicyEvaluator) GetTestMode() bool {
	return i.testMode
}

// add error
func (i *_IAMPolicyEvaluator) AddError(err error) {
	errorAssert := err.(errormgr.Error)
	i.errorMgr.StoreError(errorAssert)

}
