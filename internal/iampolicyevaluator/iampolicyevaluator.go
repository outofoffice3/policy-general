package iampolicyevaluator

import (
	"context"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/outofoffice3/policy-general/internal/awsclientmgr"
	"github.com/outofoffice3/policy-general/internal/entrymgr"
	"github.com/outofoffice3/policy-general/internal/exporter"
	"github.com/outofoffice3/policy-general/internal/metricmgr"
	"github.com/outofoffice3/policy-general/internal/shared"
)

type IAMPolicyEvaluator interface {

	// ###############################################################################################################
	// POLICY EVALUATION METHODS
	// ###############################################################################################################

	// check iam identity policies for restricted actions
	CheckNoAccess(scope string, restrictedActions []string, accountId string, results chan configServiceTypes.Evaluation) error
	// send compliance evaluation to AWS config
	SendEvaluations(evaluations []configServiceTypes.Evaluation, testMode bool) error
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
	// set event time
	SetEventTime(eventTime time.Time)
	// get event time
	GetEventTime() time.Time
	// get metric mgr
	GetMetricMgr() metricmgr.MetricMgr
}

type _IAMPolicyEvaluator struct {
	wg                *sync.WaitGroup
	resultToken       string
	scope             string
	accountId         string
	restrictedActions []string
	eventTime         time.Time
	results           chan configServiceTypes.Evaluation
	awsClientMgr      awsclientmgr.AWSClientMgr
	exporter          exporter.Exporter
	metricMgr         metricmgr.MetricMgr
}

type IAMPolicyEvaluatorInitConfig struct {
	Cfg       aws.Config
	Config    shared.Config
	AccountId string
}

// returns an instance of iam policy evaluator
func Init(config IAMPolicyEvaluatorInitConfig) IAMPolicyEvaluator {
	log.Printf("cfg received by iampolicyevaluator init : [%+v]\n", config.Config)
	// create entry mgr
	entryMgr := entrymgr.Init()

	// create aws client mgr
	awsClientMgr, err := awsclientmgr.Init(awsclientmgr.AWSClientMgrInitConfig{
		Cfg:       config.Cfg,
		Config:    config.Config,
		AccountId: config.AccountId,
	})
	// return errors
	if err != nil {
		log.Printf("error initializing aws client mgr : %v", err)
		return nil
	}

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

	mm := metricmgr.Init()

	// create iam policy evaluator
	iamPolicyEvaluator := NewIAMPolicyEvaluator(IAMPolicyEvaluatorInput{
		wg:                &sync.WaitGroup{},
		awsClientMgr:      awsClientMgr,
		exporter:          exporter,
		accountID:         config.AccountId,
		restrictedActions: config.Config.RestrictedActions,
		scope:             config.Config.Scope,
		metricMgr:         mm,
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
	metricMgr         metricmgr.MetricMgr
}

// creates a new iam policy evaluator
func NewIAMPolicyEvaluator(input IAMPolicyEvaluatorInput) IAMPolicyEvaluator {
	return &_IAMPolicyEvaluator{
		wg:                input.wg,
		resultToken:       "",
		scope:             input.scope,
		accountId:         input.accountID,
		restrictedActions: input.restrictedActions,
		results:           make(chan configServiceTypes.Evaluation, 150),
		awsClientMgr:      input.awsClientMgr,
		exporter:          input.exporter,
		metricMgr:         input.metricMgr,
	}
}

// ###############################################################################################################
// POLICY EVALUATION METHODS
// ###############################################################################################################

func processAccountRoleCompliance(restrictedActions []string, accountId string, resultsBuffer chan configServiceTypes.Evaluation, iamPolicyEvaluator IAMPolicyEvaluator) error {
	defer iamPolicyEvaluator.DecrementWaitGroup()

	var rolesWithError []string
	metricMgr := iamPolicyEvaluator.GetMetricMgr()
	// retrieve sdk iam and access analyzer clients
	awscm := iamPolicyEvaluator.GetAWSClientMgr()
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
			return err
		}
		for _, role := range listRolePage.Roles {
			metricMgr.IncrementMetric(metricmgr.TotalRoles, 1)
			log.Printf("processing compliance check for role [%v]\n", *role.Arn)
			err := processRoleCompliance(role, iamClient, accessAnalyzerClient, accountId, resultsBuffer, iamPolicyEvaluator)
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedRoles, 1)
				log.Printf("error processing compliance check for role [%v] : [%v]\n", *role.Arn, err.Error())
				rolesWithError = append(rolesWithError, *role.Arn)
				continue
			}
		}
	}
	log.Printf("iam role compliance evaluations for account [%v] completed", accountId)
	log.Printf("iam role with error : [%v]", rolesWithError)
	return nil
}

func processRoleCompliance(role types.Role, iamClient *iam.Client, accessAnalzyerClient *accessanalyzer.Client, accountId string, resultsBuffer chan configServiceTypes.Evaluation, iamPolicyEvaluator IAMPolicyEvaluator) error {
	var (
		complianceResults []shared.ComplianceResult
	)
	iamPolicyEvaluator.IncrementWaitGroup(2)
	complianceResultsChannel := make(chan shared.ComplianceResult, 100)

	// process managed policies and inline policies concurrently
	roleWg := &sync.WaitGroup{}
	roleWg.Add(2)
	go processRoleManagedPolicyCompliance(roleWg, role, iamClient, accessAnalzyerClient, accountId, complianceResultsChannel, iamPolicyEvaluator)
	go processRoleInlinePolicyCompliance(roleWg, role, iamClient, accessAnalzyerClient, accountId, complianceResultsChannel, iamPolicyEvaluator)

	// close channel when go routines complete
	go func(roleWg *sync.WaitGroup) {
		roleWg.Wait()
		close(complianceResultsChannel)
	}(roleWg)

	// read from channel, covert to aws config evaluation and send on results buffer channel
	for result := range complianceResultsChannel {
		complianceResults = append(complianceResults, result)
	}

	awsConfigEval := createAWSConfigEvaluation(shared.AwsIamRole, *role.Arn, iamPolicyEvaluator.GetEventTime(), complianceResults)
	resultsBuffer <- awsConfigEval
	log.Printf("iam role compliance evaluation for role [%v] completed : [%v] [%v] [%v] [%v] [%v]", *role.Arn,
		*awsConfigEval.ComplianceResourceId, *awsConfigEval.ComplianceResourceType, awsConfigEval.ComplianceType,
		*awsConfigEval.OrderingTimestamp, *awsConfigEval.Annotation)
	return nil
}

func processAccountUserCompliance(restrictedActions []string, accountId string, resultsBuffer chan configServiceTypes.Evaluation, iamPolicyEvaluator IAMPolicyEvaluator) error {
	defer iamPolicyEvaluator.DecrementWaitGroup()

	var usersWithError []string
	metricMgr := iamPolicyEvaluator.GetMetricMgr()
	// retrieve sdk iam and access analyzer clients
	awscm := iamPolicyEvaluator.GetAWSClientMgr()
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
			return err
		}
		for _, user := range listUserPage.Users {
			metricMgr.IncrementMetric(metricmgr.TotalUsers, 1)
			log.Printf("processing compliance check for user [%v]\n", *user.Arn)
			err := processUserCompliance(user, iamClient, accessAnalyzerClient, accountId, resultsBuffer, iamPolicyEvaluator)
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedUsers, 1)
				log.Printf("error processing compliance check for user [%v] : [%v]\n", *user.Arn, err.Error())
				usersWithError = append(usersWithError, *user.Arn)
				continue
			}
		}
	}
	log.Printf("iam user compliance evaluations for account [%v] completed", accountId)
	log.Printf("iam user with error : [%v]", usersWithError)
	return nil
}

func processUserCompliance(user types.User, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, resultsBuffer chan configServiceTypes.Evaluation, iamPolicyEvaluator IAMPolicyEvaluator) error {
	var (
		complianceResults []shared.ComplianceResult
	)
	iamPolicyEvaluator.IncrementWaitGroup(2)
	complianceResultsChannel := make(chan shared.ComplianceResult, 150)

	// process managed policies and inline policies concurrently
	userWg := &sync.WaitGroup{}
	userWg.Add(2)
	go processUserManagedPolicyCompliance(userWg, user, iamClient, accessAnalyzerClient, accountId, complianceResultsChannel, iamPolicyEvaluator)
	go processUserInlinePolicyCompliance(userWg, user, iamClient, accessAnalyzerClient, accountId, complianceResultsChannel, iamPolicyEvaluator)

	// close channel when go routines complete
	go func(roleWg *sync.WaitGroup) {
		roleWg.Wait()
		close(complianceResultsChannel)
	}(userWg)

	// read from channel, covert to aws config evaluation and send on results buffer channel
	for result := range complianceResultsChannel {
		complianceResults = append(complianceResults, result)
	}

	awsConfigEval := createAWSConfigEvaluation(shared.AwsIamUser, *user.Arn, iamPolicyEvaluator.GetEventTime(), complianceResults)
	resultsBuffer <- awsConfigEval
	log.Printf("iam role compliance evaluation for user [%v] completed : [%v] [%v] [%v] [%v] [%v]", *user.Arn,
		*awsConfigEval.ComplianceResourceId, *awsConfigEval.ComplianceResourceType, awsConfigEval.ComplianceType,
		*awsConfigEval.OrderingTimestamp, *awsConfigEval.Annotation)
	return nil
}

func processRoleManagedPolicyCompliance(wg *sync.WaitGroup, role types.Role, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, resultsBuffer chan shared.ComplianceResult, iamPolicyEvaluator IAMPolicyEvaluator) {
	defer iamPolicyEvaluator.DecrementWaitGroup()
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
			log.Printf("error retrieving list of policies for role [%v] : [%v] \n ", *role.Arn, err)
			complianceResult := shared.ComplianceResult{
				Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
				Reasons:            nil,
				Message:            err.Error(),
				PolicyDocumentName: "",
			}
			log.Printf("compliance result for role [%v] : [%+v]", *role.Arn, complianceResult)
			resultsBuffer <- complianceResult
			log.Printf("compliance result sent for role [%v]", *role.Arn)
			return
		}
		// loop through policy documents and check for compliance
		for _, policy := range listAttachedRolePoliciesPage.AttachedPolicies {
			metricMgr.IncrementMetric(metricmgr.TotalRolePolicies, 1)
			log.Printf("processing compliance check for policy [%v]\n", *policy.PolicyArn)
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
				}
				log.Printf("compliance result for role [%v] : [%+v]", *role.Arn, complianceResult)
				resultsBuffer <- complianceResult
				log.Printf("compliance result added to batch for role [%v]", *role.Arn)
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
				}
				log.Printf("compliance result for role [%v] : [%+v]", *role.Arn, complianceResult)
				resultsBuffer <- complianceResult
				log.Printf("compliance result added to batch for role [%v]", *role.Arn)
				continue
			}
			log.Printf("policy name : [%v]\n", *policy.PolicyName)
			decodedPolicyDocument, err := url.QueryUnescape(*getPolicyVersionOutput.PolicyVersion.Document)
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedRolePolicies, 1)
				log.Printf("error decoding policy document for policy [%v] : [%v] \n ", *policy.PolicyArn, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: *policy.PolicyName,
				}
				log.Printf("compliance result for role [%v] : [%+v]", *role.Arn, complianceResult)
				resultsBuffer <- complianceResult
				log.Printf("compliance result added to batch for role [%v]", *role.Arn)
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
				}
				log.Printf("compliance result for role [%v] : [%+v]", *role.Arn, complianceResult)
				resultsBuffer <- complianceResult
				log.Printf("compliance result added to batch for role [%v]", *role.Arn)
				continue
			}
			complianceResult := shared.ComplianceResult{
				Compliance:         isCompliantResult.Compliance,
				Reasons:            isCompliantResult.Reasons,
				Message:            isCompliantResult.Message,
				PolicyDocumentName: *policy.PolicyName,
			}
			log.Printf("compliance result for role [%v] : [%+v]", *role.Arn, complianceResult)
			resultsBuffer <- complianceResult
			log.Printf("compliance result added to batch for role [%v]", *role.Arn)
		}
	}
}

func processRoleInlinePolicyCompliance(wg *sync.WaitGroup, role types.Role, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, resultsBuffer chan shared.ComplianceResult, iamPolicyEvaluator IAMPolicyEvaluator) {
	defer iamPolicyEvaluator.DecrementWaitGroup()
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
			log.Printf("error retrieving list of policies for role [%v] : [%v] \n ", *role.Arn, err)
			complianceResult := shared.ComplianceResult{
				Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
				Reasons:            nil,
				Message:            err.Error(),
				PolicyDocumentName: "",
			}
			log.Printf("compliance result for role [%v] : [%+v]", *role.Arn, complianceResult)
			resultsBuffer <- complianceResult
			log.Printf("compliance result added to batch for role [%v]", *role.Arn)
			return
		}
		// loop through policy documents and check for compliance
		for _, policyName := range listRolePoliciesPage.PolicyNames {
			metricMgr.IncrementMetric(metricmgr.TotalRolePolicies, 1)
			log.Printf("processing compliance check for policy [%v]\n", policyName)
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
				}
				log.Printf("compliance result for policy [%v] : [%+v]", policyName, complianceResult)
				resultsBuffer <- complianceResult
				log.Printf("compliance result added to batch for policy [%v] in role [%v]", policyName, *role.Arn)
				continue
			}
			policyDocument := *getPolicyDocumentOutput.PolicyDocument
			log.Printf("policy name [%v]\n", policyName)
			// check if policy document is compliant
			decodedPolicyDocument, err := url.QueryUnescape(policyDocument)
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedRolePolicies, 1)
				log.Printf("error decoding policy document for policy [%v] : [%v]\n", policyName, err)
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
				}
				log.Printf("compliance result for policy [%v] : [%+v]", policyName, complianceResult)
				resultsBuffer <- complianceResult
				log.Printf("compliance result added to batch for policy [%v] in role [%v]", policyName, *role.Arn)
				continue
			}
			complianceResult := shared.ComplianceResult{
				Compliance:         isCompliantResult.Compliance,
				Reasons:            isCompliantResult.Reasons,
				Message:            isCompliantResult.Message,
				PolicyDocumentName: policyName,
			}
			log.Printf("compliance result for policy [%v] : [%+v]", policyName, complianceResult)
			resultsBuffer <- complianceResult
			log.Printf("compliance result added to batch for policy [%v] in role [%v]", policyName, *role.Arn)
		}
	}
}

func createAWSConfigEvaluation(resourceType shared.ResourceType, resourceArn string, timeStamp time.Time, complianceResults []shared.ComplianceResult) configServiceTypes.Evaluation {
	log.Printf("resource type [%v] resourceArn [%v]\n", resourceType, resourceArn)
	log.Printf("compliance results count : [%v]\n", len(complianceResults))
	// covert to aws config evaluations and send on buffered channel
	var (
		annotations           []string
		currentComplianceType configServiceTypes.ComplianceType
		evaluation            configServiceTypes.Evaluation
	)

	log.Printf("initial compliance type value : [%v]\n", currentComplianceType)
	for _, complianceResult := range complianceResults {
		// if empty, set to first compliance type from compliance results
		if currentComplianceType == "" {
			currentComplianceType = complianceResult.Compliance
		}
		log.Printf("current compliance type : [%v]\n", currentComplianceType)
		log.Printf("switch on [%v]\n", complianceResult.Compliance)
		switch complianceResult.Compliance {
		case configServiceTypes.ComplianceTypeCompliant:
			{
				log.Printf("case [%v] continuing to next record\n", complianceResult.Compliance)
				continue
			}
		case configServiceTypes.ComplianceTypeNonCompliant:
			{
				log.Printf("case [%v]\n", complianceResult.Compliance)
				//  set compliance type to NON COMPLIANT
				currentComplianceType = configServiceTypes.ComplianceTypeNonCompliant

				// extract reasons from compliance result & add to annotations
				if complianceResult.Reasons != nil {
					reasons := shared.JoinReasons(complianceResult.Reasons, ";")
					log.Printf("reasons : [%v]", reasons)
					block := complianceResult.PolicyDocumentName + " : " + reasons
					log.Printf("block : [%v]", block)
					annotations = append(annotations, block)
					log.Printf("annotations : [%v]", annotations)
				}
			}
		case configServiceTypes.ComplianceTypeNotApplicable:
			{
				log.Printf("case [%v]\n", complianceResult.Compliance)
				// if current compliance type != not applicable, set compliance type to not applicable
				if currentComplianceType != configServiceTypes.ComplianceTypeNonCompliant {
					currentComplianceType = configServiceTypes.ComplianceTypeNotApplicable
				}

				// extract messages from compliance result & add to annotations
				if complianceResult.Message != "" {
					block := complianceResult.PolicyDocumentName + " : " + complianceResult.Message
					log.Printf("block : [%v]", block)
					annotations = append(annotations, block)
					log.Printf("annotations : [%v]", annotations)
				}
			}
		default:
			{
				log.Printf("default case : [%v]", currentComplianceType)
			}
		}
	}

	log.Printf("final compliance type for resource [%v] : [%v]", resourceArn, currentComplianceType)

	// create aws config evaluation
	evaluation = configServiceTypes.Evaluation{
		ComplianceResourceId:   aws.String(resourceArn),
		ComplianceResourceType: aws.String(string(resourceType)),
		ComplianceType:         currentComplianceType,
		Annotation:             aws.String(strings.Join(annotations, "\n")),
		OrderingTimestamp:      aws.Time(timeStamp),
	}
	log.Printf("created aws config evaluation : [%v] [%v] [%v] [%v] [%v]", *evaluation.ComplianceResourceId, *evaluation.ComplianceResourceType, evaluation.ComplianceType, *evaluation.Annotation, *evaluation.OrderingTimestamp)
	return evaluation
}

func processUserManagedPolicyCompliance(wg *sync.WaitGroup, user types.User, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, resultsBuffer chan shared.ComplianceResult, iamPolicyEvaluator IAMPolicyEvaluator) {
	defer iamPolicyEvaluator.DecrementWaitGroup()
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
			log.Printf("error retrieving list of policies for user [%v] : [%v] \n ", *user.UserName, err)
			complianceResult := shared.ComplianceResult{
				Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
				Reasons:            nil,
				Message:            err.Error(),
				PolicyDocumentName: "",
			}
			log.Printf("compliance result for user [%v] : [%+v]", *user.Arn, complianceResult)
			resultsBuffer <- complianceResult
			log.Printf("compliance result added to batch for user [%v]", *user.Arn)
			return
		}
		// loop through policies attached to user
		for _, policy := range listUserPoliciesPage.AttachedPolicies {
			metricMgr.IncrementMetric(metricmgr.TotalUserPolicies, 1)
			log.Printf("managed policy [%v]\n", *policy.PolicyArn)
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
				}
				log.Printf("compliance result for policy [%v] : [%+v]", *policy.PolicyArn, complianceResult)
				resultsBuffer <- complianceResult
				log.Printf("compliance result added to batch for policy [%v] in user [%v]", *policy.PolicyArn, *user.Arn)
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
				}
				log.Printf("compliance result for policy [%v] : [%+v]", *policy.PolicyArn, complianceResult)
				resultsBuffer <- complianceResult
				log.Printf("compliance result added to batch for policy [%v] in user [%v]", *policy.PolicyArn, *user.Arn)
				continue
			}
			log.Printf("policy name : [%v]", policy.PolicyName)
			decodedPolicyDocument, err := url.QueryUnescape(*getPolicyVersionOutput.PolicyVersion.Document)
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedUserPolicies, 1)
				log.Printf("error decoding policy document for policy [%v] : [%v]\n", *policy.PolicyArn, err)
				complianceResult := shared.ComplianceResult{
					Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: *policy.PolicyName,
				}
				log.Printf("compliance result for policy [%v] : [%+v]", *policy.PolicyArn, complianceResult)
				resultsBuffer <- complianceResult
				log.Printf("compliance result added to batch for policy [%v] in user [%v]", *policy.PolicyArn, *user.Arn)
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
				}
				log.Printf("compliance result for policy [%v] : [%+v]", *policy.PolicyArn, complianceResult)
				resultsBuffer <- complianceResult
				log.Printf("compliance result added to batch for policy [%v] in user [%v]", *policy.PolicyArn, *user.Arn)
				continue
			}
			complianceResult := shared.ComplianceResult{
				Compliance:         isCompliantResult.Compliance,
				Reasons:            isCompliantResult.Reasons,
				Message:            isCompliantResult.Message,
				PolicyDocumentName: *policy.PolicyName,
			}
			log.Printf("compliance result for policy [%v] : [%+v]", *policy.PolicyArn, complianceResult)
			resultsBuffer <- complianceResult
			log.Printf("compliance result added to batch for policy [%v] in user [%v]", *policy.PolicyArn, *user.Arn)
		}
	}
}

func processUserInlinePolicyCompliance(wg *sync.WaitGroup, user types.User, iamClient *iam.Client, accessAnalyzerClient *accessanalyzer.Client, accountId string, resultsBuffer chan shared.ComplianceResult, iamPolicyEvaluator IAMPolicyEvaluator) {
	defer iamPolicyEvaluator.DecrementWaitGroup()
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
			log.Printf("error retrieving list of policies for user [%v] : [%v] \n ", *user.UserName, err)
			complianceResult := shared.ComplianceResult{
				Compliance:         configServiceTypes.ComplianceTypeNotApplicable,
				Reasons:            nil,
				Message:            err.Error(),
				PolicyDocumentName: "",
			}
			log.Printf("compliance result for user [%v] : [%+v]", *user.Arn, complianceResult)
			resultsBuffer <- complianceResult
			log.Printf("compliance result added to batch for user [%v]", *user.Arn)
			return
		}
		// loop through policy documents and check for compliance
		for _, policyName := range listUserPoliciesPage.PolicyNames {
			metricMgr.IncrementMetric(metricmgr.TotalUserPolicies, 1)
			log.Printf("processing compliance check for policy [%v]\n", policyName)
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
				}
				log.Printf("compliance result for policy [%v] : [%+v]", policyName, complianceResult)
				resultsBuffer <- complianceResult
				log.Printf("compliance result added to batch for policy [%v] in user [%v]", policyName, *user.Arn)
				continue
			}
			policyDocument := *getPolicyDocumentOutput.PolicyDocument
			log.Printf("policy name [%v]\n", policyName)
			// check if policy document is compliantcompliance result added to batch
			decodedPolicyDocument, err := url.QueryUnescape(policyDocument)
			if err != nil {
				metricMgr.IncrementMetric(metricmgr.TotalFailedUserPolicies, 1)
				log.Printf("error decoding policy document for policy [%v] : [%v]\n", policyName, err)

			}
			log.Printf("decoded policy document [%v]\n", decodedPolicyDocument)
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
				}
				log.Printf("compliance result for policy [%v] : [%+v]", policyName, complianceResult)
				resultsBuffer <- complianceResult
				log.Printf("compliance result added to batch for policy [%v] in role [%v]", policyName, *user.Arn)
				continue
			}
			complianceResult := shared.ComplianceResult{
				Compliance:         isCompliantResult.Compliance,
				Reasons:            isCompliantResult.Reasons,
				Message:            isCompliantResult.Message,
				PolicyDocumentName: policyName,
			}
			log.Printf("compliance result for policy [%v] : [%+v]", policyName, complianceResult)
			resultsBuffer <- complianceResult
			log.Printf("compliance result added to batch for policy [%v] in user [%v]", policyName, *user.Arn)
		}
	}
}

func processAllCompliance(restrictedActions []string, accountId string, results chan configServiceTypes.Evaluation, iamPolicyEvaluator IAMPolicyEvaluator) {
	iamPolicyEvaluator.IncrementWaitGroup(2)
	go processAccountRoleCompliance(restrictedActions, accountId, results, iamPolicyEvaluator)
	go processAccountUserCompliance(restrictedActions, accountId, results, iamPolicyEvaluator)
}

// send evaluation to aws config
func (i *_IAMPolicyEvaluator) SendEvaluations(evaluations []configServiceTypes.Evaluation, testMode bool) error {
	metricMgr := i.GetMetricMgr()
	// retrieve sdk config client
	accountId := i.accountId
	awscm := i.GetAWSClientMgr()
	client, _ := awscm.GetSDKClient(accountId, awsclientmgr.CONFIG)
	configClient := client.(*configservice.Client)

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
		return err
	}
	metricMgr.IncrementMetric(metricmgr.TotalEvaluations, int32(len(evaluations)))
	return nil
}

// check no access
func (i *_IAMPolicyEvaluator) CheckNoAccess(scope string, restrictedActions []string, accountId string, resultsBuffer chan configServiceTypes.Evaluation) error {
	log.Printf("scope=%s, restrictedActions=%v, accountId=%s\n", scope, restrictedActions, accountId)
	switch strings.ToLower(scope) {
	case ROLES:
		{
			i.IncrementWaitGroup(1)
			go processAccountRoleCompliance(restrictedActions, accountId, resultsBuffer, i)
		}
	case USERS:
		{
			i.IncrementWaitGroup(1)
			go processAccountUserCompliance(restrictedActions, accountId, resultsBuffer, i)
		}
	case ALL:
		{
			processAllCompliance(restrictedActions, accountId, resultsBuffer, i)
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

// set event time
func (i *_IAMPolicyEvaluator) SetEventTime(eventTime time.Time) {
	i.eventTime = eventTime
}

// get event time
func (i *_IAMPolicyEvaluator) GetEventTime() time.Time {
	return i.eventTime
}

// get metric mgr
func (i *_IAMPolicyEvaluator) GetMetricMgr() metricmgr.MetricMgr {
	return i.metricMgr
}
