package evaluationmgr

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/policy-general/internal/awsclientmgr"
	"github.com/outofoffice3/policy-general/internal/errormgr"
	"github.com/outofoffice3/policy-general/internal/metricmgr"
	"github.com/outofoffice3/policy-general/internal/shared"
	"github.com/outofoffice3/policy-general/internal/writer"
	"github.com/stretchr/testify/assert"
)

func TestEvaluationMgr(t *testing.T) {
	assertion := assert.New(t)
	cfg, err := config.LoadDefaultConfig(context.Background())
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
		Scope:    "all",
		TestMode: "true",
	}
	accountId := "033197602013"
	awscm, err := awsclientmgr.Init(awsclientmgr.AWSClientMgrInitConfig{
		Ctx:       context.Background(),
		Cfg:       cfg,
		Config:    config,
		AccountId: accountId,
	})
	assertion.NoError(err)
	assertion.NotNil(awscm)

	mm := metricmgr.Init()
	evalMgr := Init(EvaluationMgrInitConfig{
		ResultToken:  "",
		TestMode:     true,
		AccountId:    accountId,
		AwsClientMgr: awscm,
		MetricMgr:    mm,
	})
	assertion.NotNil(evalMgr)
	evalMgrAssert := evalMgr.(*_EvaluationMgr)
	assertion.NotNil(evalMgrAssert)
	assertion.NotNil(evalMgrAssert.awsClientMgr)
	assertion.NotNil(evalMgrAssert.metricMgr)
	assertion.True(evalMgrAssert.testMode)
	assertion.Equal(accountId, evalMgrAssert.accountId)
	assertion.Equal("", evalMgrAssert.resultToken)

	evalChan := make(chan configServiceTypes.Evaluation, 125)
	errorChan := make(chan error, 5)
	errMgr := errormgr.NewErrorMgr()

	// listen for errors
	errorWg := new(sync.WaitGroup)
	errorWg.Add(1)
	go func() {
		defer errorWg.Done()
		errMgr.ListenForErrors(errorChan)
	}()

	// listen for evaluations
	evalWg := new(sync.WaitGroup)
	evalWg.Add(1)
	go func() {
		defer evalWg.Done()
		evalMgr.ListenForEvaluations(evalChan, errorChan)
	}()

	// create 200 evaluations in a loop
	for i := 0; i < 200; i++ {
		// convert index to string
		strIndex := strconv.Itoa(i)
		evalChan <- configServiceTypes.Evaluation{
			ComplianceResourceId:   aws.String("test " + strIndex),
			ComplianceResourceType: aws.String(string(shared.AwsIamRole)),
			ComplianceType:         configServiceTypes.ComplianceTypeNonCompliant,
			OrderingTimestamp:      aws.Time(time.Now().UTC()),
			Annotation:             aws.String("test annotation " + strIndex),
		}
	}

	// close channels
	close(evalChan)
	evalWg.Wait()

	totalEvaluations, ok := mm.GetMetric(metricmgr.TotalEvaluations)
	assertion.True(ok)
	assertion.Equal(int32(200), totalEvaluations)

	writer, err := writer.Init(writer.WriterInitConfig{
		AccountId:    accountId,
		AWSClientMgr: awscm,
	})
	assertion.NoError(err)
	assertion.NotNil(writer)

	// create test records for csv file
	filename := "test.csv"
	header := []string{"ComplianceResourceId", "ComplianceResourceType", "ComplianceType", "OrderingTimestamp", "Annotation"}
	records := [][]string{
		{"test 0", string(shared.AwsIamRole), "NON_COMPLIANT", time.Now().UTC().Format(time.RFC3339), "test annotation 0"},
		{"test 1", string(shared.AwsIamRole), "NON_COMPLIANT", time.Now().UTC().Format(time.RFC3339), "test annotation 1"},
		{"test 2", string(shared.AwsIamRole), "NON_COMPLIANT", time.Now().UTC().Format(time.RFC3339), "test annotation 2"},
		{"test 3", string(shared.AwsIamRole), "NON_COMPLIANT", time.Now().UTC().Format(time.RFC3339), "test annotation 3"},
		{"test 4", string(shared.AwsIamRole), "NON_COMPLIANT", time.Now().UTC().Format(time.RFC3339), "test annotation 4"},
		{"test 5", string(shared.AwsIamRole), "NON_COMPLIANT", time.Now().UTC().Format(time.RFC3339), "test annotation 5"},
	}

	evalMgr.WriteCSV(filename, header, records, writer, errorChan)
	// delete file
	err = writer.DeleteTempFile(filename)
	assertion.NoError(err)

	close(errorChan)
	errorWg.Wait()

	errorSlice := errMgr.GetErrors()
	assertion.Len(errorSlice, 0)

}
