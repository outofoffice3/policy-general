package metricmgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetricMgr(t *testing.T) {
	assertion := assert.New(t)

	mm := Init()
	assertion.NotNil(mm)

	// validate each metric type

	// total roles
	value, ok := mm.GetMetric(TotalRoles)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total role policies
	value, ok = mm.GetMetric(TotalRolePolicies)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total users
	value, ok = mm.GetMetric(TotalUsers)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total user policies
	value, ok = mm.GetMetric(TotalUserPolicies)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total failed roles
	value, ok = mm.GetMetric(TotalFailedRoles)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total failed role policies
	value, ok = mm.GetMetric(TotalFailedRolePolicies)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total failed user
	value, ok = mm.GetMetric(TotalFailedUserPolicies)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total faild user policies
	value, ok = mm.GetMetric(TotalFailedUserPolicies)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// ##############################################
	// increment metric
	// ##############################################

	// total roles
	err := mm.IncrementMetric(TotalRoles, 1)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalRoles)
	assertion.True(ok)
	assertion.Equal(int32(1), value)

	// total role policies
	err = mm.IncrementMetric(TotalRolePolicies, 2)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalRolePolicies)
	assertion.True(ok)
	assertion.Equal(int32(2), value)

	// total users
	err = mm.IncrementMetric(TotalUsers, 3)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalUsers)
	assertion.True(ok)
	assertion.Equal(int32(3), value)

	// total user policies
	err = mm.IncrementMetric(TotalUserPolicies, 4)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalUserPolicies)
	assertion.True(ok)
	assertion.Equal(int32(4), value)

	// total failed roles
	err = mm.IncrementMetric(TotalFailedRoles, 5)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalFailedRoles)
	assertion.True(ok)
	assertion.Equal(int32(5), value)

	// total failed role policies
	err = mm.IncrementMetric(TotalFailedRolePolicies, 6)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalFailedRolePolicies)
	assertion.True(ok)
	assertion.Equal(int32(6), value)

	// total failed users
	err = mm.IncrementMetric(TotalFailedUsers, 7)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalFailedUsers)
	assertion.True(ok)
	assertion.Equal(int32(7), value)

	// total failed user policies
	err = mm.IncrementMetric(TotalFailedUserPolicies, 8)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalFailedUserPolicies)
	assertion.True(ok)
	assertion.Equal(int32(8), value)

	// ##############################################
	// decrement metric
	// ##############################################

	// total roles
	err = mm.DecrementMetric(TotalRoles, 1)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalRoles)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total role policies
	err = mm.DecrementMetric(TotalRolePolicies, 2)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalRolePolicies)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total users
	err = mm.DecrementMetric(TotalUsers, 3)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalUsers)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total user policies
	err = mm.DecrementMetric(TotalUserPolicies, 4)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalUserPolicies)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total failed roles
	err = mm.DecrementMetric(TotalFailedRoles, 5)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalFailedRoles)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total failed role policies
	err = mm.DecrementMetric(TotalFailedRolePolicies, 6)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalFailedRolePolicies)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total failed users
	err = mm.DecrementMetric(TotalFailedUsers, 7)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalFailedUsers)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// total failed user policies
	err = mm.DecrementMetric(TotalFailedUserPolicies, 8)
	assertion.NoError(err)
	value, ok = mm.GetMetric(TotalFailedUserPolicies)
	assertion.True(ok)
	assertion.Equal(int32(0), value)

	// #####################################
	// errors
	// #####################################

	err = mm.IncrementMetric("TotalRoles", -1)
	assertion.Error(err)

	err = mm.DecrementMetric("TotalRoles", -1)
	assertion.Error(err)

	number := int32(0)
	err = mm.setMetric(TotalRoles, &number)
	assertion.Error(err)

}
