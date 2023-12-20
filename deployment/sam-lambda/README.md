# Deployment Guide

## Requirements

* AWS CLI already configured with Administrator permission
* SAM CLI - [Install the SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)

## Build & Deploy

1. **SAM build**

Navigate to your /sam-lambda directory and execute the following command:

```bash 
sam build 
```
This command compiles source code, downloads dependencies, and creates deployment artifacts.

2. **SAM deploy**: 

After building, deploy your application using:
```bash 
sam deploy --guided
```

The --guided flag initiates an interactive deployment process, prompting you for the necessary parameters like the AWS region, stack name, and any specific configurations required for your AWS Lambda function and custom AWS Config rule.

# Appendix

### Golang installation

Please ensure Go 1.x (where 'x' is the latest version) is installed as per the instructions on the official golang website: https://golang.org/doc/install

A quickstart way would be to use Homebrew, chocolatey or your linux package manager.

#### Homebrew (Mac)

Issue the following command from the terminal:

```shell
brew install golang
```

If it's already installed, run the following command to ensure it's the latest version:

```shell
brew update
brew upgrade golang
```

#### Chocolatey (Windows)

Issue the following command from the powershell:

```shell
choco install golang
```

If it's already installed, run the following command to ensure it's the latest version:

```shell
choco upgrade golang
```
