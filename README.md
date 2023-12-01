**DISCLAIMER: UNDER DEVELOPMENT.  WILL BE READY FOR RELEASE AFTER RE:INVENT 2023**

<div align="center">
 <img src="./graphics/generalshao.gif" alt="walk" width="250"/>
</div>

# Policy General

Policy General is a solution designed to enforce compliance of IAM (Identity and Access Management) policies. It is responsible for checking whether IAM policies adhere to predefined sets of restricted actions, as specified in a configuration file.

## Table of Contents
- [Overview](#overview)
  - [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [How it works](#how-it-works)
  - [Configuration](#configuration)
  - [Initialization](#initialization)
  - [Execution](#execution)
- [How to deploy](#how-to-deploy-step-by-step)
- [License](#license)

## Overview

This solution enhances security and compliance by enforcing IAM policy restrictions across multiple AWS accounts. The integration with AWS Config facilitates continuous detection through scheduled rule runs, providing flexibility for customized checks on a weekly, daily, or hourly basis.

Policy General consists of the following components: 

1. Custom AWS config rule 
2. Lambda funciton integrated with custom AWS config rule
3. Execution role for lambda function

Below are the permissions used for the execution role: 

- logs:CreateLogGroup
- logs:CreateLogStream
- logs:PutLogEvents
- xray:PutTelemetryRecords
- xray:PutTraceSegments
- s3:GetObject
- s3:PutObject
- iam:ListUsers
- iam:ListRoles
- iam:ListAttachedUserPolicies
- iam:ListAttachedRolePolicies
- config:PutEvaluations
- access-analyzer:CheckAccessNotGranted

```json 
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "XRay",
      "Effect": "Allow",
      "Action": [
        "xray:PutTelemetryRecords",
        "xray:PutTraceSegments"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3BucketAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::your-specific-bucket-name/*"
    },
    {
      "Sid": "IAMActions",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ConfigAndAccessAnalyzer",
      "Effect": "Allow",
      "Action": [
        "config:PutEvaluations",
        "access-analyzer:CheckAccessNotGranted"
      ],
      "Resource": "*"
    }
  ]
}
```

### Project Structure 
```bash 
|-- deployment/           # deployment files
  |-- cdk-config-rule/    # cdk app for deploying aws config rule
  |-- sam-lambda/         # sam template for deploying lambda func        
|-- pkg/                  # packages 
  |-- evaluator/          # evaluator package
    |-- evalevents/       # evaluator event types
    |-- evaltypes/        # evaluator types
```

## Prerequisites

Before deploying this solution, ensure your local development environment is equipped with the following:

- **Go Programming Language (v1.20+)**:
Download and install Go from the [official website](https://go.dev/dl/).

- **AWS SAM CLI**:
Install AWS SAM CLI by following the [AWS SAM CLI Installation Guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html).

- **AWS CDK**:
Install AWS CDK by following the [AWS CDK Getting Started Guide](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html#getting_started_install).

### IAM Role Requirements

1. IAM roles for each accountId specified in the `config.json` file.  They will require the minimum permissions: 

- iam:ListUsers
- iam:ListRoles
- iam:ListAttachedUserPolicies
- iam:ListAttachedRolePolicies
- access-analyzer:CheckAccessNotGranted

```json 
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAM & Access Analyzer Actions",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "access-analyzer:CheckAccessNotGranted"
      ],
      "Resource": "*"
    }
  ]
}
```
The aws config rule lambda function needs to assume all of these roles.  Add a trust policy to each role that will allow the lambda function's execution role to assume it.  

For example, your `config.json` file might look like this:

```json 
{
  "awsAccounts": [
    {
      "accountId": "123456789101",
      "roleName": "arn:aws:iam::123456789101:role/your-role-name"
    },
    {
      "accountId": "098765432109",
      "roleName": "arn:aws:iam::098765432109:role/your-role-name"
    }
  ],
  "actions": [
    "s3:GetObject",
    "s3:PutObject",
    "ec2:DescribeInstances",
    "lambda:InvokeFunction"
  ],
  "scope": "all" // valid values = roles, user or all
}
```
So in this example, you would need to ensure that the IAM role's specified above, `arn:aws:iam::123456789101:role/your-role-name` and `arn:aws:iam::098765432109:role/your-role-name` both have a trust policy allowing the lambda function's execution role to assume it.  For example, below is a sample trust policy : 

```json 
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid" : "Trust between AWS Config Rule Lambda Execution Role",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::AWS_CONFIG_RULE_LAMBDA_ACCOUNT_ID:role/AWS_CONFIG_RULE_LAMBDA_ROLE_NAME"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

```

## How it works

To understand how Policy General works behind the scenes, I will explain the config file it relies on and what occurs in the Initialization and Execution phase. 

### Configuration
Policy General is configured using a JSON file stored in S3. This configuration file specifies AWS account IDs, IAM service roles, a list of restricted actions, and a scope attribute.

```json 
{
  "awsAccounts": [
    {
      "accountId": "your_account_id_1",
      "roleName": "YourServiceRoleName1"
    },
    {
      "accountId": "your_account_id_2",
      "roleName": "YourServiceRoleName2"
    }
  ],
  "actions": [
    "s3:GetObject",
    "s3:PutObject",
    "ec2:DescribeInstances",
    "lambda:InvokeFunction"
  ],
  "scope": "all" // valid values = roles, user or all
}
```

- **awsAccounts**: An array of objects containing AWS account IDs and IAM role names that the Lambda function can assume.

- **actions**: An array of strings specifying the allowed or restricted actions that will be checked against IAM policies.

- **scope**: A string indicating the scope of IAM policies to be evaluated. It can take one of the two values: "roles," "users," or "all."

### Initialization 

1. Reads `CONFIG_FILE_BUCKET_NAME` and `CONFIG_FILE_KEY` from environment variable, loads config file from s3 and serializes file into **evaltypes.Config** struct 
```go
// Config represents the overall configuration structure.
type Config struct {
	AWSAccounts       []AWSAccount `json:"awsAccounts"`
	RestrictedActions []string     `json:"actions"`
	Scope             string       `json:"scope"`
}

 // AWSAccount represents an AWS account with its associated IAM role.
type AWSAccount struct {
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
}
```
2. Validate the scope attribute is either "roles", "users" or "all". 
3. Validate the restricted actions match regex pattern 	
```go
// <service-namespace>:<action-name>
```
4. Create assume role provider and create iam & access analyzer SDK clients with the assumed roles from the config file.  Add the SDK clients to the client map with the accountID as the key.

### Execution 

1. Receive cloudwatch event and serialize event.Details into **evalevents.ConfigEvent type**
```go 
type ConfigEvent struct {
	Version          string `json:"version"`
	InvokingEvent    string `json:"invokingEvent"`
	RuleParameters   string `json:"ruleParameters"`
	ResultToken      string `json:"resultToken"`
	EventLeftScope   bool   `json:"eventLeftScope"`
	ExecutionRoleArn string `json:"executionRoleArn"`
	ConfigRuleArn    string `json:"configRuleArn"`
	ConfigRuleName   string `json:"configRuleName"`
	ConfigRuleID     string `json:"configRuleId"`
	AccountID        string `json:"accountId"`
	EvaluationMode   string `json:"evaluationMode"`
}
```
2. For each AWS account Id, it will spawn a go routine and process the compliance of the IAM policies concurrently.
3. Results will be sent on a buffered channel and published to AWS Config

## How to Deploy (step by step)

- [Readme for Policy General deployment](/deployment/README.md)

## License 

The project is license under the [Apache 2.0 License](./LICENSE)


## Contributions
Open for contributions, just open a pull request!