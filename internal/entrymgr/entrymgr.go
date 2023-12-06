package entrymgr

import (
	"errors"

	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/policy-general/internal/evaluator/evaltypes"
)

type EntryMgr interface {
	// add entry
	Add(entry evaltypes.ExecutionLogEntry) error
	// get entries
	GetEntries(compliance string) ([]evaltypes.ExecutionLogEntry, error)
}

type _EntryMgr struct {
	insufficientData []evaltypes.ExecutionLogEntry
	compliant        []evaltypes.ExecutionLogEntry
	nonCompliant     []evaltypes.ExecutionLogEntry
}

// create new entry manager
func NewEntryMgr() EntryMgr {
	return &_EntryMgr{
		insufficientData: []evaltypes.ExecutionLogEntry{},
		compliant:        []evaltypes.ExecutionLogEntry{},
		nonCompliant:     []evaltypes.ExecutionLogEntry{},
	}
}

// add entry
func (em *_EntryMgr) Add(entry evaltypes.ExecutionLogEntry) error {
	// based on compliance, add entry to corresponding slice
	switch entry.Compliance {
	case string(configServiceTypes.ComplianceTypeInsufficientData):
		{
			em.insufficientData = append(em.insufficientData, entry)
		}
	case string(configServiceTypes.ComplianceTypeCompliant):
		{
			em.compliant = append(em.compliant, entry)
		}
	case string(configServiceTypes.ComplianceTypeNonCompliant):
		{
			em.nonCompliant = append(em.nonCompliant, entry)
		}
	default:
		{
			return errors.New("unknown compliance type" + "[" + entry.Compliance + "]")
		}
	}
	return nil
}

// get entries
func (em *_EntryMgr) GetEntries(compliance string) ([]evaltypes.ExecutionLogEntry, error) {
	// based on compliance, return corresponding slice
	switch compliance {
	case string(configServiceTypes.ComplianceTypeInsufficientData):
		{
			return em.insufficientData, nil
		}
	case string(configServiceTypes.ComplianceTypeCompliant):
		{
			return em.compliant, nil
		}
	case string(configServiceTypes.ComplianceTypeNonCompliant):
		{
			return em.nonCompliant, nil
		}
	default:
		{
			return nil, errors.New("unknown compliance type" + "[" + compliance + "]")
		}
	}
}
