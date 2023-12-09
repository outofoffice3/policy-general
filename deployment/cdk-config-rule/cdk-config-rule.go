package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsconfig"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"

	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
)

type DeploymentStackProps struct {
	awscdk.StackProps
}

func PolicyGeneralStack(scope constructs.Construct, id string, props *DeploymentStackProps) awscdk.Stack {
	var sprops awscdk.StackProps
	if props != nil {
		sprops = props.StackProps
	}
	stack := awscdk.NewStack(scope, &id, &sprops)

	// A custom rule that runs on periodic schedule
	_ = awsconfig.NewCustomRule(stack, jsii.String("checkNoAccess AWS Config Rule"), &awsconfig.CustomRuleProps{
		Description:               jsii.String("Rule to ensure IAM identity policies don't contain restricted actions specified by Security / Compliance team"),
		LambdaFunction:            awslambda.Function_FromFunctionArn(stack, jsii.String("policy general lambda"), jsii.String("arn:aws:lambda:us-east-1:033197602013:function:policy-general-checkNoAccess-2-AWSConfigRuleLambda-OxdTiDJc0oHo")),
		ConfigurationChanges:      jsii.Bool(false),
		Periodic:                  jsii.Bool(true),
		MaximumExecutionFrequency: awsconfig.MaximumExecutionFrequency_TWENTY_FOUR_HOURS,
	})

	return stack
}

func main() {
	defer jsii.Close()

	app := awscdk.NewApp(nil)

	PolicyGeneralStack(app, "policy-general-configRule-2023", &DeploymentStackProps{
		awscdk.StackProps{
			Env: env(),
		},
	})

	app.Synth(nil)
}

func env() *awscdk.Environment {

	return &awscdk.Environment{
		Account: jsii.String("033197602013"),
		Region:  jsii.String("us-east-1"),
	}
}
