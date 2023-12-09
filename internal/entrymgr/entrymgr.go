package entrymgr

import (
	"errors"
	"time"

	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/common/logger"
	"github.com/outofoffice3/policy-general/internal/shared"
)

// EntryMgr stores & retrieves execution log entries for evaluator pkg
type EntryMgr interface {
	// add entry
	Add(entry shared.ExecutionLogEntry) error
	// get entries
	GetEntries(compliance string) ([]shared.ExecutionLogEntry, error)
	// get logger
	GetLogger() logger.Logger
}

type _EntryMgr struct {
	insufficientData []shared.ExecutionLogEntry
	compliant        []shared.ExecutionLogEntry
	nonCompliant     []shared.ExecutionLogEntry
	logger           logger.Logger
}

func Init(sos logger.Logger) EntryMgr {
	em := newEntryMgr(sos)
	log := em.GetLogger()
	log.Infof("entry manager initialized")
	return em
}

// create new entry manager
func newEntryMgr(sos logger.Logger) EntryMgr {
	if sos == nil {
		sos = logger.NewConsoleLogger(logger.LogLevelInfo)
	}
	em := &_EntryMgr{
		insufficientData: []shared.ExecutionLogEntry{},
		compliant:        []shared.ExecutionLogEntry{},
		nonCompliant:     []shared.ExecutionLogEntry{},
		logger:           sos,
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
			em.logger.Errorf("unknown compliance type: [%s]", entry.Compliance)
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
			em.logger.Errorf("unknown compliance type: [%s]", compliance)
			return nil, errors.New("unknown compliance type" + "[" + compliance + "]")
		}
	}
}

// get logger
func (em *_EntryMgr) GetLogger() logger.Logger {
	return em.logger
}

func CreateExecutionLogEntry(evaluation shared.ComplianceEvaluation) shared.ExecutionLogEntry {
	var entry shared.ExecutionLogEntry
	entry.AccountId = evaluation.AccountId
	entry.Arn = evaluation.Arn
	entry.Compliance = string(evaluation.ComplianceResult.Compliance)
	entry.ErrMsg = evaluation.ErrMsg
	entry.ResourceType = string(evaluation.ResourceType)
	entry.Timestamp = evaluation.Timestamp.Format(time.RFC3339)
	return entry
}
