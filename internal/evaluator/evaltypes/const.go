package evaltypes

type AwsConfigCompliance string
type ResourceType string

const (
	COMPLIANT      AwsConfigCompliance = "COMPLIANT"
	NON_COMPLIANT  AwsConfigCompliance = "NON_COMPLIANT"
	NOT_APPLICABLE AwsConfigCompliance = "NOT_APPLICABLE"

	AWS_IAM_ROLE  ResourceType = "AWS::IAM::ROLE"
	AWS_IAM_USER  ResourceType = "AWS::IAM:USER"
	NOT_SPECIFIED ResourceType = "NOT_SPECIFIED"

	CONFIG_FILE_BUCKET_NAME string = "CONFIG_FILE_BUCKET_NAME"
	CONFIG_FILE_KEY         string = "CONFIG_FILE_KEY"
	EXECUTION_LOG_FILE_NAME string = "EXECUTION_LOG_FILE_NAME"
)
