package handle

import (
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/policy-general/internal/iampolicyevaluator"
	"github.com/outofoffice3/policy-general/internal/shared"
)

func HandleConfigEvent(event shared.ConfigEvent, policyEvaluator iampolicyevaluator.IAMPolicyEvaluator) error {
	sos := policyEvaluator.GetLogger()
	policyEvaluator.SetResultToken(event.ResultToken)
	resultsBuffer := make(chan shared.ComplianceEvaluation, 100)
	awsclientmgr := policyEvaluator.GetAWSClientMgr()
	scope := policyEvaluator.GetScope()
	restrictedActions := policyEvaluator.GetRestrictedActions()
	for _, accountId := range awsclientmgr.GetAccountIds() {
		policyEvaluator.IncrementWaitGroup(1)
		go policyEvaluator.CheckNoAccess(scope, restrictedActions, accountId, resultsBuffer)
		sos.Debugf("checkNoAccess for [%s] in account [%s]", scope, restrictedActions)
	}

	// close channel when all goroutines complete
	go func(pe iampolicyevaluator.IAMPolicyEvaluator, results shared.ComplianceEvaluation) {
		pe.Wait()
		close(resultsBuffer)
		sos.Debugf("resultsBuffer closed")
	}(policyEvaluator, <-resultsBuffer)

	var batchAwsConfigEvaluations []configServiceTypes.Evaluation
	maxBatchSize := 100
	currentIndex := 0
	exporter := policyEvaluator.GetExporter()
	// process compliance evaluations
	for result := range resultsBuffer {
		policyEvaluator.DecrementWaitGroup()
		sos.Debugf("result: %v", result)

		// add compliance evaulation to exporter
		err := exporter.AddEntry(result)
		// return errors
		if err != nil {
			sos.Errorf("failed to add entry: %v", err)
			return err
		}

		awsConfigEvaluation := shared.CreateAWSConfigEvaluation(result)
		batchAwsConfigEvaluations = append(batchAwsConfigEvaluations, awsConfigEvaluation)
		currentIndex++

		if currentIndex == maxBatchSize {
			policyEvaluator.SendEvaluations(batchAwsConfigEvaluations)
			currentIndex = 0
			continue
		}
	}
	// send remaining results to aws config
	policyEvaluator.SendEvaluations(batchAwsConfigEvaluations)

	// write results to csv
	err := exporter.WriteToCSV(shared.EXECUTION_LOG_FILE_NAME)
	// return errors
	if err != nil {
		sos.Errorf("failed to write csv: %v", err)
		return err
	}
	sos.Debugf("csv written")

	// export csv file to S3 bucket
	fileKey, err := exporter.ExportToS3(shared.CONFIG_FILE_BUCKET_NAME)
	if err != nil {
		sos.Errorf("failed to write file to S3: %v", err)
		return err
	}
	sos.Debugf("file written to S3: %s", fileKey)

	return nil
}
