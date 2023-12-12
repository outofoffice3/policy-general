package handle

import (
	"log"

	"github.com/aws/aws-lambda-go/events"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/policy-general/internal/iampolicyevaluator"
	"github.com/outofoffice3/policy-general/internal/shared"
)

func HandleConfigEvent(event events.ConfigEvent, policyEvaluator iampolicyevaluator.IAMPolicyEvaluator) error {
	policyEvaluator.SetResultToken(event.ResultToken)
	resultsBuffer := make(chan shared.ComplianceEvaluation, 100)
	awsclientmgr := policyEvaluator.GetAWSClientMgr()
	scope := policyEvaluator.GetScope()
	log.Printf("scope: [%s]\n", scope)
	restrictedActions := policyEvaluator.GetRestrictedActions()
	log.Printf("restrictedActions: [%v]\n", restrictedActions)
	for _, accountId := range awsclientmgr.GetAccountIds() {
		policyEvaluator.IncrementWaitGroup(1)
		go policyEvaluator.CheckNoAccess(scope, restrictedActions, accountId, resultsBuffer)
		log.Printf("checkNoAccess for [%s] in account [%s]\n", scope, accountId)
	}

	// close channel when all goroutines complete
	go func(pe iampolicyevaluator.IAMPolicyEvaluator, results shared.ComplianceEvaluation) {
		pe.Wait()
		close(resultsBuffer)
		log.Printf("resultsBuffer closed")
	}(policyEvaluator, <-resultsBuffer)

	var batchAwsConfigEvaluations []configServiceTypes.Evaluation
	maxBatchSize := 100
	currentIndex := 0
	exporter := policyEvaluator.GetExporter()
	// process compliance evaluations
	for result := range resultsBuffer {
		policyEvaluator.DecrementWaitGroup()
		log.Printf("result: [%v]\n", result)

		// add compliance evaulation to exporter
		err := exporter.AddEntry(result)
		// return errors
		if err != nil {
			log.Printf("failed to add entry: [%v]\n", err)
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
	err := exporter.WriteToCSV(string(shared.ExecutionLogFileName))
	// return errors
	if err != nil {
		log.Printf("failed to write csv: [%v]\n", err)
		return err
	}
	log.Println("csv written")

	// export csv file to S3 bucket
	fileKey, err := exporter.ExportToS3(string(shared.ConfigFileBucketName))
	if err != nil {
		log.Printf("failed to write file to S3: [%v]\n", err)
		return err
	}
	log.Printf("file written to S3: [%s]\n", fileKey)

	return nil
}
