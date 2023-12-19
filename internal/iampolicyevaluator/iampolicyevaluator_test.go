package iampolicyevaluator

import (
	"context"
	"log"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/outofoffice3/policy-general/internal/metricmgr"
	"github.com/outofoffice3/policy-general/internal/shared"
	"github.com/stretchr/testify/assert"
)

func TestIAMPolicyEvaluator(t *testing.T) {
	assertion := assert.New(t)

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithSharedConfigProfile("PLACEDHOLER"),
		config.WithRegion("PLACEHOLDER"))
	assertion.NoError(err)
	assertion.NotNil(cfg)

	config := shared.Config{
		AWSAccounts: []shared.AWSAccount{
			{
				AccountID: "PLACEHOLDER",
				RoleName:  "PLACEHOLDER",
			},
		},
		RestrictedActions: []string{
			"s3:GetObject",
			"s3:PutObject",
			"ec2:DescribeInstances",
			"lambda:InvokeFunction",
		},
		Scope:    "all",
		TestMode: "true",
	}
	accountId := "PLACEHOLDER"
	ctx, cancel := context.WithCancel(context.Background())
	iamPolicyEvaluator := Init(IAMPolicyEvaluatorInitConfig{
		Cfg:         cfg,
		Config:      config,
		Ctx:         ctx,
		CancelFunc:  cancel,
		ResultToken: "fake_token",
		AccountId:   accountId,
	})

	metricMgr := iamPolicyEvaluator.GetMetricMgr()
	assertion.NotNil(metricMgr, "metricMgr is nil")
	assertion.NotNil(iamPolicyEvaluator)

	iamPolicyEvaluator.CheckAccessNotGranted(config.Scope, iamPolicyEvaluator.GetRestrictedActions(), accountId)

	gt := iamPolicyEvaluator.GetGoTracker()
	gt.WriteActiveGoroutinesToCSV("activeGoRoutines.csv")
	gt.WriteAllGoroutinesToCSV("allGoRoutines.csv")
	gt.WriteAllDefersToCSV("allDefers.csv")
	assertion.True(gt.AreAllGoroutinesClosed())
	totalEvaluations, ok := metricMgr.GetMetric(metricmgr.TotalEvaluations)
	assertion.True(ok)
	log.Printf("total evaluations [%v]\n", totalEvaluations)
}
