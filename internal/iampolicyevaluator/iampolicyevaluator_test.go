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
		config.WithSharedConfigProfile("logadmin"),
		config.WithRegion("us-east-1"))
	assertion.NoError(err)
	assertion.NotNil(cfg)

	config := shared.Config{
		AWSAccounts: []shared.AWSAccount{
			{
				AccountID: "017608207428",
				RoleName:  "arn:aws:iam::017608207428:role/checkNoAccessPolicyGeneral2023",
			},
		},
		RestrictedActions: []string{
			"s3:GetObject",
			"s3:PutObject",
			"ec2:DescribeInstances",
			"lambda:InvokeFunction",
		},
		Scope: "all",
	}
	accountId := "033197602013"
	ctx, cancel := context.WithCancel(context.Background())
	iamPolicyEvaluator := Init(IAMPolicyEvaluatorInitConfig{
		Cfg:        cfg,
		Config:     config,
		AccountId:  accountId,
		Ctx:        ctx,
		CancelFunc: cancel,
	})

	metricMgr := iamPolicyEvaluator.GetMetricMgr()
	assertion.NotNil(metricMgr, "metricMgr is nil")
	assertion.NotNil(iamPolicyEvaluator)

	iamPolicyEvaluator.CheckAccessNotGranted(config.Scope, iamPolicyEvaluator.GetRestrictedActions(), accountId)

	/*
		totalRoles, ok := metricMgr.GetMetric(metricmgr.TotalRoles)
		assertion.True(ok)
		assertion.Equal(int32(70), totalRoles)
		log.Printf("total roles : [%v]", totalRoles)

		totalUsers, ok := metricMgr.GetMetric(metricmgr.TotalUsers)
		assertion.True(ok)
		assertion.Equal(int32(1), totalUsers)
		log.Printf("total users : [%v]", totalUsers)

		totalRolePolicies, ok := metricMgr.GetMetric(metricmgr.TotalRolePolicies)
		assertion.True(ok)
		log.Printf("total role policies : [%v]", totalRolePolicies)

		totalUserPolicies, ok := metricMgr.GetMetric(metricmgr.TotalUserPolicies)
		assertion.True(ok)
		log.Printf("total user policies : [%v]", totalUserPolicies)

		totalFailedRoles, ok := metricMgr.GetMetric(metricmgr.TotalFailedRoles)
		assertion.True(ok)
		log.Printf("total failed roles : [%v]", totalFailedRoles)

		totalFailedUsers, ok := metricMgr.GetMetric(metricmgr.TotalFailedUsers)
		assertion.True(ok)
		log.Printf("total failed users : [%v]", totalFailedUsers)

		totalFailedRolePolicies, ok := metricMgr.GetMetric(metricmgr.TotalFailedRolePolicies)
		assertion.True(ok)
		log.Printf("total failed role policies : [%v]", totalFailedRolePolicies)

		totalFailedUserPolicies, ok := metricMgr.GetMetric(metricmgr.TotalFailedUserPolicies)
		assertion.True(ok)
		log.Printf("total failed user policies : [%v]", totalFailedUserPolicies)
	*/
	gt := iamPolicyEvaluator.GetGoTracker()
	gt.WriteActiveGoroutinesToCSV("activeGoRoutines.csv")
	gt.WriteAllGoroutinesToCSV("allGoRoutines.csv")
	gt.WriteAllDefersToCSV("allDefers.csv")
	assertion.True(gt.AreAllGoroutinesClosed())
	totalEvaluations, ok := metricMgr.GetMetric(metricmgr.TotalEvaluations)
	assertion.True(ok)
	log.Printf("total evaluations [%v]\n", totalEvaluations)
}
