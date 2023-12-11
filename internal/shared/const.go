package shared

const (
	ConfigFileBucketName                 S3BucketName = "policy-general-2023"
	CheckAccessNotGrantedonfigFileObjKey S3ObjectKey  = "config.json"
	ExecutionLogFileName                 S3ObjectKey  = "checkNoAccess-aws-config.csv"

	EnvBucketName    EnvVar = "CONFIG_FILE_BUCKET_NAME"
	EnvConfigFileKey EnvVar = "CONFIG_FILE_KEY"
	EnvAWSAccountID  EnvVar = "AWS_ACCOUNT_ID"

	NotSpecified ResourceType = "not specified"
	AwsIamRole   ResourceType = "AWS::IAM::Role"
	AwsIamUser   ResourceType = "AWS::IAM::User"
)
