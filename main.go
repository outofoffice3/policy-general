package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outofoffice3/common/logger"
	"github.com/outofoffice3/policy-general/handle"
	"github.com/outofoffice3/policy-general/internal/iampolicyevaluator"
	"github.com/outofoffice3/policy-general/internal/shared"
)

var (
	complianceEvaluator iampolicyevaluator.IAMPolicyEvaluator
)

func handler(ctx context.Context, event events.CloudWatchEvent) error {
	// retrieve logger
	sos := complianceEvaluator.GetLogger()
	sos.Debugf("cloudwatch event [%+v]", event)
	// Deserialize the event into ConfigEvent
	var configEvent shared.ConfigEvent
	if err := json.Unmarshal(event.Detail, &configEvent); err != nil {
		return fmt.Errorf("failed to unmarshal Config event: %v", err)
	}
	sos.Debugf("config event [%+v]", configEvent)

	// Handle config event & start service execution
	err := handle.HandleConfigEvent(configEvent, complianceEvaluator)
	if err != nil {
		return err
	}
	complianceEvaluator.Wait() // wait for execution to complete
	return nil
}

func main() {
	lambda.Start(handler)
}

func init() {
	logger := logger.NewConsoleLogger(logger.LogLevelDebug)
	logger.Infof("main init started")
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		logger.Errorf("failed to load SDK config, %v", err)
		panic("failed to load sdk config")
	}
	logger.Infof("SDK config loaded [%+v]", cfg)

	// read env vars for config file location
	configBucketName := os.Getenv(string(shared.EnvBucketName))
	logger.Debugf("config bucket name : [%s]", configBucketName)
	configObjKey := os.Getenv(string(shared.EnvConfigFileKey))
	logger.Debugf("config object key : [%s]", configObjKey)
	accountId := os.Getenv(string(shared.EnvAWSAccountID))
	logger.Debugf("account id : [%s]", accountId)

	if configBucketName == "" || configObjKey == "" || accountId == "" {
		logger.Errorf("env vars not set")
		panic("env vars not set")
	}

	// retrieve config file from s3
	s3Client := s3.NewFromConfig(cfg)
	getObjectOutput, err := s3Client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(configBucketName),
		Key:    aws.String(configObjKey),
	})
	// return errors
	if err != nil {
		logger.Errorf("failed to get object from s3, %v", err)
		panic("failed to get object from s3")
	}
	logger.Infof("config file retrieved")

	// convert to shared.Config struct
	var config shared.Config
	objectContent, err := io.ReadAll(getObjectOutput.Body)
	// return errors
	if err != nil {
		logger.Errorf("failed to read object content, %v", err)
		panic("failed to read object content")
	}
	err = json.Unmarshal(objectContent, &config)
	// return errors
	if err != nil {
		logger.Errorf("failed to unmarshal object content, %v", err)
		panic("failed to unmarshal object content")
	}

	// check if scope is valid
	if !shared.IsValidScope(config.Scope) {
		logger.Errorf("invalid scope [%s]", config.Scope)
		panic("invalid scope")
	}

	// check if actions are valid
	for _, restrictedAction := range config.RestrictedActions {
		if !shared.IsValidAction(restrictedAction) {
			logger.Errorf("invalid action [%s]", restrictedAction)
			panic("invalid action: " + "[ " + restrictedAction + " ]")
		}
	}
	logger.Infof("config file parsed")

	complianceEvaluator = iampolicyevaluator.Init(logger, shared.CheckNoAccessConfig{
		Config:    config,
		AccountId: accountId,
	})
}
