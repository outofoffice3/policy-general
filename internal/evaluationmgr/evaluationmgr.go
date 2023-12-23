package evaluationmgr

import (
	"context"
	"log"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/policy-general/internal/awsclientmgr"
	"github.com/outofoffice3/policy-general/internal/metricmgr"
	"github.com/outofoffice3/policy-general/internal/writer"
)

// EvaluationMgr stores & retrieves execution log entries for evaluator pkg
type EvaluationMgr interface {
	// listen for evaluations
	ListenForEvaluations(evalChan <-chan configServiceTypes.Evaluation, errorChan chan<- error)
	// send evaluations
	SendEvaluations(client *configservice.Client, evaluations []configServiceTypes.Evaluation, mm metricmgr.MetricMgr, errorChan chan<- error)
	// get entries
	GetEvaluations() []configServiceTypes.Evaluation
	// write evaluations to csv file
	WriteCSV(filename string, header []string, records [][]string, writer writer.Writer, errorChan chan<- error) string
	// write evaluations to s3
	ExportToS3(bucket string, key string, prefix string, data []byte, writer writer.Writer, errorChan chan<- error)
	// get writer
	GetWriter() writer.Writer
}

type _EvaluationMgr struct {
	accountId    string
	resultToken  string
	testMode     bool
	writer       writer.Writer
	entries      []configServiceTypes.Evaluation
	awsClientMgr awsclientmgr.AWSClientMgr
	metricMgr    metricmgr.MetricMgr
}

type EvaluationMgrInitConfig struct {
	ResultToken  string
	TestMode     bool
	AccountId    string
	AwsClientMgr awsclientmgr.AWSClientMgr
	MetricMgr    metricmgr.MetricMgr
}

func Init(config EvaluationMgrInitConfig) EvaluationMgr {
	em := newEvaluationMgr(config)
	log.Println("entry manager initialized")
	return em
}

// create new entry manager
func newEvaluationMgr(config EvaluationMgrInitConfig) EvaluationMgr {
	writer, err := writer.Init(writer.WriterInitConfig{
		AWSClientMgr: config.AwsClientMgr,
		AccountId:    config.AccountId,
	})
	if err != nil {
		log.Fatalf("error creating new evaluation mgr : [%v]\n", err.Error())
	}
	em := &_EvaluationMgr{
		accountId:    config.AccountId,
		resultToken:  config.ResultToken,
		testMode:     config.TestMode,
		awsClientMgr: config.AwsClientMgr,
		metricMgr:    config.MetricMgr,
		entries:      make([]configServiceTypes.Evaluation, 0),
		writer:       writer,
	}
	return em
}

// get entries
func (em *_EvaluationMgr) GetEvaluations() []configServiceTypes.Evaluation {
	return em.entries
}

// send evaluations
func (em *_EvaluationMgr) SendEvaluations(client *configservice.Client, evaluations []configServiceTypes.Evaluation, mm metricmgr.MetricMgr, errorChan chan<- error) {
	_, err := client.PutEvaluations(context.Background(), &configservice.PutEvaluationsInput{
		ResultToken: aws.String(em.resultToken),
		Evaluations: evaluations,
		TestMode:    em.testMode,
	})
	log.Printf("sent %d evaluations\n", len(evaluations))
	mm.IncrementMetric(metricmgr.TotalEvaluations, int32(len(evaluations)))
	// send errors to error channel
	if err != nil {
		errorChan <- err
		mm.IncrementMetric(metricmgr.TotalFailedEvaluations, int32(len(evaluations)))
	}
}

// write evaluations to csv file
func (em *_EvaluationMgr) WriteCSV(filename string, header []string, records [][]string, writer writer.Writer, errorChan chan<- error) string {
	name, err := writer.WriteCSV(filename, header, records)
	if err != nil {
		errorChan <- err
	}
	return name
}

// write evaluations to s3
func (em *_EvaluationMgr) ExportToS3(bucket string, key string, prefix string, data []byte, writer writer.Writer, errorChan chan<- error) {
	err := writer.ExportToS3(bucket, key, prefix, data)
	if err != nil {
		errorChan <- err
	}
}

// listen for evaluations
func (em *_EvaluationMgr) ListenForEvaluations(evalChan <-chan configServiceTypes.Evaluation, errorChan chan<- error) {
	var (
		evalWg       *sync.WaitGroup
		maxBatchSize int
		index        int
	)
	// process evaluations in batches of 100
	client, _ := em.awsClientMgr.GetSDKClient(em.accountId, awsclientmgr.CONFIG)
	configClient := client.(*configservice.Client)

	index = 0
	maxBatchSize = 100
	evalWg = new(sync.WaitGroup)
	for eval := range evalChan {
		log.Printf("received evaluation: [%v]\n", *eval.ComplianceResourceId)
		// add evaluation to array
		em.entries = append(em.entries, eval)
		index++
		// if array is full, send evaluations to aws config and reset array
		log.Printf("current index : [%v]\n", index)
		if index >= maxBatchSize {
			// send evaluations in goroutine
			items := em.entries
			evalWg.Add(1)
			go func(items []configServiceTypes.Evaluation) {
				defer evalWg.Done()
				em.SendEvaluations(configClient, items, em.metricMgr, errorChan)
			}(items)
		} else {
			continue
		}
		evalWg.Wait()
		em.entries = make([]configServiceTypes.Evaluation, 0)
		index = 0
	}
	// send remaining evaluations
	if len(em.entries) > 0 {
		evalWg.Add(1)
		go func(items []configServiceTypes.Evaluation) {
			defer evalWg.Done()
			em.SendEvaluations(configClient, items, em.metricMgr, errorChan)
		}(em.entries)
		evalWg.Wait()
	}
}

// get writer
func (em *_EvaluationMgr) GetWriter() writer.Writer {
	return em.writer
}
