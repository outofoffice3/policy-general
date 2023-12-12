package entrymgr

import (
	"errors"
	"log"
	"time"

	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/policy-general/internal/shared"
)

// EntryMgr stores & retrieves execution log entries for evaluator pkg
type EntryMgr interface {
	// add entry
	Add(entry shared.ExecutionLogEntry) error
	// get entries
	GetEntries(compliance string) ([]shared.ExecutionLogEntry, error)
}

type _EntryMgr struct {
	insufficientData []shared.ExecutionLogEntry
	compliant        []shared.ExecutionLogEntry
	nonCompliant     []shared.ExecutionLogEntry
}

func Init() EntryMgr {
	em := newEntryMgr()
	log.Println("entry manager initialized")
	return em
}

// create new entry manager
func newEntryMgr() EntryMgr {
	em := &_EntryMgr{
		insufficientData: []shared.ExecutionLogEntry{},
		compliant:        []shared.ExecutionLogEntry{},
		nonCompliant:     []shared.ExecutionLogEntry{},
	}
	return em
}

// add entry
func (em *_EntryMgr) Add(entry shared.ExecutionLogEntry) error {
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
			log.Printf("unknown compliance type: [%s]\n", entry.Compliance)
			return errors.New("unknown compliance type" + "[" + entry.Compliance + "]")
		}
	}
	return nil
}

// get entries
func (em *_EntryMgr) GetEntries(compliance string) ([]shared.ExecutionLogEntry, error) {
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
			log.Printf("unknown compliance type: [%s]\n", compliance)
			return nil, errors.New("unknown compliance type" + "[" + compliance + "]")
		}
	}
}

func CreateExecutionLogEntry(evaluation shared.ComplianceEvaluation) shared.ExecutionLogEntry {
	reasons := shared.JoinReasons(evaluation.ComplianceResult.Reasons, ";")
	entry := shared.ExecutionLogEntry{
		AccountId:    evaluation.AccountId,
		Arn:          evaluation.Arn,
		ResourceType: string(evaluation.ResourceType),
		Compliance:   string(evaluation.ComplianceResult.Compliance),
		Reasons:      reasons,
		Message:      evaluation.ComplianceResult.Message,
		ErrMsg:       evaluation.ErrMsg,
		Timestamp:    evaluation.Timestamp.Format(time.RFC3339),
	}
	return entry
}
