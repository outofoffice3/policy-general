package worker

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/policy-general/internal/awsclientmgr"
	"github.com/outofoffice3/policy-general/internal/shared"
	"github.com/outofoffice3/policy-general/internal/writer"
)

type EvaluationWorker struct {
	ctx          context.Context
	accountId    string
	resultToken  string
	id           int
	testMode     bool
	wg           *sync.WaitGroup
	errorChan    chan error
	evaluations  chan configServiceTypes.Evaluation
	awsClientMgr awsclientmgr.AWSClientMgr
	writer       writer.Writer
}

type EvaluationWorkerInput struct {
	Ctx          context.Context
	AccountId    string
	ResultToken  string
	Id           int
	TestMode     bool
	Wg           *sync.WaitGroup
	ErrorChan    chan error
	Evaluations  chan configServiceTypes.Evaluation
	AwsClientMgr awsclientmgr.AWSClientMgr
	Writer       writer.Writer
}

func NewEvaluationWorker(input EvaluationWorkerInput) *EvaluationWorker {
	return &EvaluationWorker{
		ctx:          input.Ctx,
		accountId:    input.AccountId,
		resultToken:  input.ResultToken,
		errorChan:    input.ErrorChan,
		evaluations:  input.Evaluations,
		id:           input.Id,
		testMode:     input.TestMode,
		wg:           input.Wg,
		awsClientMgr: input.AwsClientMgr,
		writer:       input.Writer,
	}
}

func (w *EvaluationWorker) Run() {
	defer w.wg.Done()
	var (
		batch        []configServiceTypes.Evaluation
		csvRecords   [][]string
		maxBatchSize int
	)
	batch = []configServiceTypes.Evaluation{}
	maxBatchSize = 100
	csvRecords = [][]string{}
	for {
		select {
		case <-w.evaluations:
			{
				// add record to batch
				batch = append(batch, configServiceTypes.Evaluation{})

				// if length is >= maxBatchSize, send to aws config
				if len(batch) >= maxBatchSize {
					// send batch to aws config
					client, _ := w.awsClientMgr.GetSDKClient(w.accountId, awsclientmgr.CONFIG)
					configClient := client.(*configservice.Client)
					_, err := configClient.PutEvaluations(w.ctx, &configservice.PutEvaluationsInput{
						ResultToken: aws.String(w.resultToken),
						Evaluations: batch,
						TestMode:    w.testMode,
					})
					// send errors to error channel
					if err != nil {
						w.errorChan <- err
					}

					// clear batch
					batch = []configServiceTypes.Evaluation{}
					log.Printf("EvaluationWorker [%d]: sent batch to aws config\n", w.id)
					continue
				}
			}
		case <-w.ctx.Done():
			{
				log.Printf("EvaluationWorker [%d]: context done\n", w.id)

				// send remaining batch to aws config
				if len(batch) > 0 {
					client, _ := w.awsClientMgr.GetSDKClient(w.accountId, awsclientmgr.CONFIG)
					configClient := client.(*configservice.Client)

					// send evaluations to aws config
					_, err := configClient.PutEvaluations(w.ctx, &configservice.PutEvaluationsInput{
						ResultToken: aws.String(w.resultToken),
						Evaluations: batch,
						TestMode:    w.testMode,
					})
					// send errors to error channel
					if err != nil {
						w.errorChan <- err
					}
				}

				// add evaluations to csv records [][]string
				for _, evaluation := range batch {
					csvRecords = append(csvRecords, []string{
						*evaluation.ComplianceResourceId,                  // compliance resource id (e.g. aws:acm:certificate:12345678-1234-1234-1234-123456789012:domain-validation-options)
						*evaluation.ComplianceResourceType,                // compliance resource type (e.g. AWS::IAM::ROLE)
						string(evaluation.ComplianceType),                 // compliance type (e.g. COMPLIANT, NONCOMPLIANT)
						*evaluation.Annotation,                            // annotation
						evaluation.OrderingTimestamp.Format(time.RFC3339), // timestamp
					})
				}
				header := []string{
					"ComplianceResourceId",
					"ComplianceResourceType",
					"ComplianceType",
					"Annotation",
					"OrderingTimestamp",
				}

				result, err := w.writer.WriteCSV(string(shared.ExecutionLogFileName), header, csvRecords)
				if err != nil {
					w.errorChan <- err
				}
				log.Printf("EvaluationWorker [%v]: wrote [%s] to csv file\n", w.id, result)

				// write results to csv file
				return
			}
		}
	}
}
