package handle

import (
	"log"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/outofoffice3/policy-general/internal/iampolicyevaluator"
)

func HandleConfigEvent(event events.ConfigEvent, policyEvaluator iampolicyevaluator.IAMPolicyEvaluator) error {
	policyEvaluator.SetResultToken(event.ResultToken)
	policyEvaluator.SetEventTime(time.Now())
	awsclientmgr := policyEvaluator.GetAWSClientMgr()
	scope := policyEvaluator.GetScope()
	log.Printf("scope: [%s]\n", scope)
	restrictedActions := policyEvaluator.GetRestrictedActions()
	log.Printf("restrictedActions: [%v]\n", restrictedActions)
	log.Printf("account Ids : [%v]", awsclientmgr.GetAccountIds())
	accountsWg := &sync.WaitGroup{}
	for _, accountId := range awsclientmgr.GetAccountIds() {
		accountsWg.Add(1)
		go policyEvaluator.CheckAccessNotGranted(scope, restrictedActions, accountId)
		log.Printf("checkNoAccess for [%s] in account [%s]\n", scope, accountId)
	}
	accountsWg.Wait()
	log.Printf("all accounts completed successfully")

	return nil
}
