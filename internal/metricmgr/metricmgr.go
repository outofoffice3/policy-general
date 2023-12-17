package metricmgr

import (
	"errors"
	"log"
	"sync/atomic"
)

type MetricMgr interface {
	// Increment metric
	IncrementMetric(metric Metric, value int32) error
	// Decrement metric
	DecrementMetric(metric Metric, value int32) error
	// Retreive Metric
	GetMetric(metric Metric) (int32, bool)
	// set metric
	setMetric(metric Metric, ptr *int32) error
}

type _MetricMgr struct {
	metrics map[Metric]*int32
}

func Init() MetricMgr {
	metricMgr := NewMetricMgr()
	// initialize all metrics to 0 and set Atomic

	// set totals metrics
	totalRoles := int32(0)
	metricMgr.setMetric(TotalRoles, &totalRoles)
	totalRolePolicies := int32(0)
	metricMgr.setMetric(TotalRolePolicies, &totalRolePolicies)
	totalUsers := int32(0)
	metricMgr.setMetric(TotalUsers, &totalUsers)
	totalUserPolicies := int32(0)
	metricMgr.setMetric(TotalUserPolicies, &totalUserPolicies)

	// set failure metrics
	totalFailedRoles := int32(0)
	metricMgr.setMetric(TotalFailedRoles, &totalFailedRoles)
	totalFailedRolePolicies := int32(0)
	metricMgr.setMetric(TotalFailedRolePolicies, &totalFailedRolePolicies)
	totalFailedUsers := int32(0)
	metricMgr.setMetric(TotalFailedUsers, &totalFailedUsers)
	totalFailedUserPolicies := int32(0)
	metricMgr.setMetric(TotalFailedUserPolicies, &totalFailedUserPolicies)

	// set evaluation metrics
	totalEvaluations := int32(0)
	metricMgr.setMetric(TotalEvaluations, &totalEvaluations)
	totalFailedEvaluations := int32(0)
	metricMgr.setMetric(TotalFailedEvaluations, &totalFailedEvaluations)

	return metricMgr

}

func NewMetricMgr() MetricMgr {
	return &_MetricMgr{
		metrics: make(map[Metric]*int32),
	}
}

func (m *_MetricMgr) IncrementMetric(metric Metric, value int32) error {
	if _, ok := m.GetMetric(metric); !ok {
		return errors.New("metric " + string(metric) + " not found")
	}
	atomic.AddInt32(m.metrics[metric], value)
	return nil
}

func (m *_MetricMgr) DecrementMetric(metric Metric, value int32) error {
	if _, ok := m.GetMetric(metric); !ok {
		return errors.New("metric " + string(metric) + " not found")
	}
	atomic.AddInt32(m.metrics[metric], -value)
	return nil
}

func (m *_MetricMgr) GetMetric(metric Metric) (int32, bool) {
	if _, ok := m.metrics[metric]; !ok {
		log.Printf("Metric %s not found\n", metric)
		return int32(0), false
	}
	return atomic.LoadInt32(m.metrics[metric]), true
}

func (m *_MetricMgr) setMetric(metric Metric, ptr *int32) error {
	if _, ok := m.metrics[metric]; ok {
		return errors.New("metric " + string(metric) + " already exists")
	}
	m.metrics[metric] = ptr
	return nil
}
