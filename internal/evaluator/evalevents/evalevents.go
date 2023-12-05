package evalevents

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
