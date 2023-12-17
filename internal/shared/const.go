package shared

const (
	ConfigFileBucketName                  S3BucketName = "policy-general-2023"
	CheckAccessNotGrantedConfigFileObjKey S3ObjectKey  = "config.json"
	ExecutionLogFileName                  S3ObjectKey  = "checkAccessNotGranted-results.csv"
	ErrorLogFileObjectKey                 S3ObjectKey  = "checkAccessNotGranted-errors.csv"

	EnvBucketName    EnvVar = "CONFIG_FILE_BUCKET_NAME"
	EnvConfigFileKey EnvVar = "CONFIG_FILE_KEY"
	EnvAWSAccountID  EnvVar = "AWS_ACCOUNT_ID"

	NotSpecified ResourceType = "not specified"
	AwsIamRole   ResourceType = "AWS::IAM::Role"
	AwsIamUser   ResourceType = "AWS::IAM::User"

	UsEast1 AwsRegion = "us-east-1"
	UsEast2 AwsRegion = "us-east-2"
	UsWest1 AwsRegion = "us-west-1"
	UsWest2 AwsRegion = "us-west-2"
)
