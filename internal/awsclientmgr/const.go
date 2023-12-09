package awsclientmgr

type AWSServiceName string

const (
	IAM    AWSServiceName = "IAM"
	AA     AWSServiceName = "AccessAnalyzer"
	S3     AWSServiceName = "S3"
	CONFIG AWSServiceName = "AWS Config"
)
