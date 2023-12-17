package exporter

const (
	ComplianceType       = "ComplianceType"
	ComplianceResourceId = "ComplianceResourceId"
	Annotation           = "Annotation"
	OrderingTimestamp    = "OrderingTimestamp"

	AccountId          = "AccountId"
	ResourceType       = "ResourceType"
	PolicyDocumentName = "PolicyDocumentName"
	Message            = "Message"

	NoAllowRulesError = "InvalidParameterException: You must include at least one allow statement for analysis"
)

var (
	EvaluationHeader = []string{ComplianceResourceId, ComplianceType, Annotation, OrderingTimestamp}
	ErrorHeader      = []string{AccountId, ResourceType, PolicyDocumentName, Message}
)
