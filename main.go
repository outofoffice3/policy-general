package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/outofoffice3/common/logger"
	"github.com/outofoffice3/policy-general/pkg/evaluator"
	"github.com/outofoffice3/policy-general/pkg/evaluator/evalevents"
)

var (
	complianceEvaluator evaluator.Evaluator
)

func handler(ctx context.Context, event events.CloudWatchEvent) error {
	// retrieve logger
	sos := complianceEvaluator.GetLogger()
	sos.Debugf("cloudwatch event [%+v]", event)
	// Deserialize the event into ConfigEvent
	var configEvent evalevents.ConfigEvent
	if err := json.Unmarshal(event.Detail, &configEvent); err != nil {
		return fmt.Errorf("failed to unmarshal Config event: %v", err)
	}
	sos.Debugf("config event [%+v]", configEvent)

	// Handle config event & start service execution
	err := complianceEvaluator.HandleConfigEvent(configEvent)
	// return errors
	if err != nil {
		evaluator.HandleError(err)
	}
	return nil
}

func main() {
	lambda.Start(handler)
}

func init() {
	logger := logger.NewConsoleLogger(logger.LogLevelDebug)
	complianceEvaluator = evaluator.Init(logger)
}
