package metricmgr

type Metric string

const (
	TotalRoles        Metric = "totalRoles"
	TotalRolePolicies Metric = "totalRolePolicies"
	TotalUsers        Metric = "totalUsers"
	TotalUserPolicies Metric = "totalUserPolicies"
	TotalEvaluations  Metric = "totalEvaluations"

	TotalFailedRoles        Metric = "totalFailedRoles"
	TotalFailedRolePolicies Metric = "totalFailedRolePolicies"
	TotalFailedUsers        Metric = "totalFailedUsers"
	TotalFailedUserPolicies Metric = "totalFailedUserPolicies"
	TotalFailedEvaluations  Metric = "totalFailedEvaluations"

	TotalCacheHits Metric = "totalCacheHits"
)
