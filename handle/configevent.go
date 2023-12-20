package handle

import (
	"log"

	"github.com/aws/aws-lambda-go/events"
	"github.com/outofoffice3/policy-general/internal/iampolicyevaluator"
)

func HandleConfigEvent(event events.ConfigEvent, policyEvaluator iampolicyevaluator.IAMPolicyEvaluator) {
	awsclientmgr := policyEvaluator.GetAWSClientMgr()
	scope := policyEvaluator.GetScope()
	log.Printf("scope: [%s]\n", scope)
	restrictedActions := policyEvaluator.GetRestrictedActions()
	log.Printf("restrictedActions: [%v]\n", restrictedActions)
	log.Printf("account Ids : [%v]", awsclientmgr.GetAccountIds())
	accountIds := awsclientmgr.GetAccountIds()
	policyEvaluator.CheckAccessNotGranted(scope, restrictedActions, accountIds)
	log.Printf("checkNoAccess for [%s] in accounts [%s]\n", scope, accountIds)
	log.Printf("all accounts completed successfully")
}
