package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outofoffice3/policy-general/handle"
	"github.com/outofoffice3/policy-general/internal/iampolicyevaluator"
	"github.com/outofoffice3/policy-general/internal/shared"
)

var (
	complianceEvaluator iampolicyevaluator.IAMPolicyEvaluator
)

func handler(ctx context.Context, event events.ConfigEvent) error {
	// retrieve logger
	log.Printf("aws config event : [%+v]\n", event)
	// unmarshal invoking event from incoming event
	var invokingEvent shared.InvokingEvent
	err := json.Unmarshal([]byte(event.InvokingEvent), &invokingEvent)
	// return errors
	if err != nil {
		log.Printf("failed to unmarshal invoking event: [%v]\n", err)
		return err
	}
	log.Printf("invoking event : [%+v]\n", invokingEvent)

	// ############################################################
	// INITIALIZE IAM POLICY EVALUATOR INTERFACE
	// ############################################################

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(string(shared.UsEast1)),
		config.WithRetryMode(aws.RetryModeStandard),
		config.WithRetryMaxAttempts(3))
	if err != nil {
		panic("failed to load sdk config")
	}
	log.Printf("initial config : [%+v]", cfg)

	// read env vars for config file location
	configBucketName := os.Getenv(string(shared.EnvBucketName))
	log.Printf("config bucket name : [%s]", configBucketName)
	configObjKey := os.Getenv(string(shared.EnvConfigFileKey))
	log.Printf("config object key : [%s]", configObjKey)

	if configBucketName == "" || configObjKey == "" {
		log.Printf("env vars not set")
		panic("env vars not set")
	}

	// retrieve config file from s3
	s3Cfg := cfg.Copy()
	s3Client := s3.NewFromConfig(s3Cfg)
	getObjectOutput, err := s3Client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(configBucketName),
		Key:    aws.String(configObjKey),
	})
	// return errors
	if err != nil {
		log.Printf("failed to get object from s3, %v", err)
		panic("failed to get object from s3")
	}
	log.Printf("config file retrieved")

	var config shared.Config
	objectContent, err := io.ReadAll(getObjectOutput.Body)
	// return errors
	if err != nil {
		log.Printf("failed to read object content, %v", err)
		panic("failed to read object content")
	}
	log.Printf("config file content : [%s]", string(objectContent))
	err = json.Unmarshal(objectContent, &config)
	// return errors
	if err != nil {
		log.Printf("failed to unmarshal object content, %v", err)
		panic("failed to unmarshal object content")
	}
	log.Printf("unmarshaled config file : [%+v]", config)

	// check if scope is valid
	if !shared.IsValidScope(config.Scope) {
		log.Printf("invalid scope [%s]", config.Scope)
		panic("invalid scope")
	}

	// check if actions are valid
	for _, restrictedAction := range config.RestrictedActions {
		log.Printf("restricted action: [%v]\n", restrictedAction)
		if !shared.IsValidAction(restrictedAction) {
			log.Printf("invalid action [%s]", restrictedAction)
			panic("invalid action: " + "[ " + restrictedAction + " ]")
		}
	}
	log.Printf("config file parsed")

	// ############################################################

	log.Printf("input cfg for iampolicyevaluator : [%+v]", cfg)
	ctxWithCancel, cancel := context.WithCancel(context.Background())
	complianceEvaluator = iampolicyevaluator.Init(iampolicyevaluator.IAMPolicyEvaluatorInitConfig{
		Cfg:        cfg,
		Config:     config,
		AccountId:  event.AccountID,
		Ctx:        ctxWithCancel,
		CancelFunc: cancel,
	})

	// Handle config event & start service execution
	err = handle.HandleConfigEvent(event, complianceEvaluator)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	lambda.Start(handler)
}
