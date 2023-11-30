**DISCLAIMER: UNDER DEVELOPMENT.  WILL BE READY FOR RELEASE AFTER RE:INVENT 2023**

<div align="center">
 <img src="./graphics/generalshao.gif" alt="walk" width="250"/>
</div>

# Policy General

Policy General is a solution designed to enforce compliance of IAM (Identity and Access Management) policies. It is responsible for checking whether IAM policies adhere to predefined sets of restricted actions, as specified in a configuration file.

## Table of Contents
- [Overview](#overview)
- [How it works](#how-it-works)
  - [Configuration](#configuration)
  - [Initialization](#initialization)
  - [Execution](#execution)
- [How to deploy](#how-to-deploy-step-by-step)
- [License](#license)

## Overview

Policy General has two components: 

1. Custom AWS Config Rule 
2. Lambda Function integrated with the custom rule

This solution enhances security and compliance by enforcing IAM policy restrictions across multiple AWS accounts. The integration with AWS Config facilitates continuous detection through scheduled rule runs, providing flexibility for customized checks on a weekly, daily, or hourly basis.

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

1. Reads `CONFIG_FILE_BUCKET_NAME` and `CONFIG_FILE_KEY` from environment variable, loads config file from s3 and serializes file into **pgtypes.Config** struct 
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

1. Receive cloudwatch event and serialize event.Details into **pgevents.ConfigEvent type**
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
We are open for contributions! 