package handle

import (
	"log"
	"time"

	"github.com/aws/aws-lambda-go/events"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/policy-general/internal/iampolicyevaluator"
	"github.com/outofoffice3/policy-general/internal/shared"
)

func HandleConfigEvent(event events.ConfigEvent, policyEvaluator iampolicyevaluator.IAMPolicyEvaluator) error {

	policyEvaluator.SetResultToken(event.ResultToken)
	policyEvaluator.SetEventTime(time.Now())
	resultsBuffer := make(chan configServiceTypes.Evaluation, 100)
	awsclientmgr := policyEvaluator.GetAWSClientMgr()
	scope := policyEvaluator.GetScope()
	log.Printf("scope: [%s]\n", scope)
	restrictedActions := policyEvaluator.GetRestrictedActions()
	log.Printf("restrictedActions: [%v]\n", restrictedActions)
	log.Printf("account Ids : [%v]", awsclientmgr.GetAccountIds())
	for _, accountId := range awsclientmgr.GetAccountIds() {
		policyEvaluator.IncrementWaitGroup(1)
		go policyEvaluator.CheckNoAccess(scope, restrictedActions, accountId, resultsBuffer)
		log.Printf("checkNoAccess for [%s] in account [%s]\n", scope, accountId)
	}

	// close channel when all goroutines complete
	go func(pe iampolicyevaluator.IAMPolicyEvaluator, results configServiceTypes.Evaluation) {
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
		log.Printf("result: [%v] [%v] [%v] [%v]", *result.ComplianceResourceId, *result.ComplianceResourceType, result.ComplianceType, *result.Annotation)

		// add compliance evaulation to exporter
		err := exporter.AddEntry(result)
		// return errors
		if err != nil {
			log.Printf("failed to add entry: [%v]\n", err)
			return err
		}

		// ##############################################
		// CREATE AWS CONFIG EVALUATIONS BASED ON RESULT
		// ##############################################

		// if compliance type is INSUFFICIENT DATA, discard record
		if result.ComplianceType == configServiceTypes.ComplianceTypeInsufficientData {
			continue
		}

		batchAwsConfigEvaluations = append(batchAwsConfigEvaluations, result)
		currentIndex++

		if currentIndex == maxBatchSize {
			err := policyEvaluator.SendEvaluations(batchAwsConfigEvaluations, false)
			// return errors
			if err != nil {
				log.Printf("failed to send evaluation to aws config: [%v]\n", err)
				return err
			}
			currentIndex = 0
			continue
		}
	}
	// send remaining results to aws config
	policyEvaluator.SendEvaluations(batchAwsConfigEvaluations, false)

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
