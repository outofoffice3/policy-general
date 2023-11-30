package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/outofoffice3/common/logger"
	"github.com/outofoffice3/policy-general/pkg/evaluator"
	"github.com/outofoffice3/policy-general/pkg/pgevents"
)

var (
	sos                 logger.Logger
	complianceEvalutaor evaluator.Evaluator
)

func handler(ctx context.Context, event events.CloudWatchEvent) error {
	sos.Debugf("cloudwatch event [%+v]", event)
	// Deserialize the event into ConfigEvent
	var configEvent pgevents.ConfigEvent
	if err := json.Unmarshal(event.Detail, &configEvent); err != nil {
		return fmt.Errorf("failed to unmarshal Config event: %v", err)
	}
	sos.Debugf("config event [%+v]", configEvent)
	err := complianceEvalutaor.HandleConfigEvent(configEvent)

	if err != nil {
		return fmt.Errorf("failed to handle Config event: %v", err)
	}

	return nil
}

func main() {
	lambda.Start(handler)
}

func init() {
	sos = logger.NewConsoleLogger(logger.LogLevelDebug)
	complianceEvalutaor = evaluator.NewEvaluator()
}
