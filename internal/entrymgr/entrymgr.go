package entrymgr

import (
	"errors"
	"log"

	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

// EntryMgr stores & retrieves execution log entries for evaluator pkg
type EntryMgr interface {
	// add entry
	AddEntry(entry configServiceTypes.Evaluation) error
	// get entries
	GetEntries(compliance string) ([]configServiceTypes.Evaluation, error)
}

type _EntryMgr struct {
	insufficientData []configServiceTypes.Evaluation
	compliant        []configServiceTypes.Evaluation
	nonCompliant     []configServiceTypes.Evaluation
	notApplicable    []configServiceTypes.Evaluation
}

func Init() EntryMgr {
	em := newEntryMgr()
	log.Println("entry manager initialized")
	return em
}

// create new entry manager
func newEntryMgr() EntryMgr {
	em := &_EntryMgr{
		insufficientData: []configServiceTypes.Evaluation{},
		compliant:        []configServiceTypes.Evaluation{},
		nonCompliant:     []configServiceTypes.Evaluation{},
		notApplicable:    []configServiceTypes.Evaluation{},
	}
	return em
}

// add entry
func (em *_EntryMgr) AddEntry(entry configServiceTypes.Evaluation) error {
	// based on compliance, add entry to corresponding slice
	log.Printf("adding entry: [%+v]\n", entry)
	switch entry.ComplianceType {
	case configServiceTypes.ComplianceTypeInsufficientData:
		{
			em.insufficientData = append(em.insufficientData, entry)
		}
	case configServiceTypes.ComplianceTypeCompliant:
		{
			em.compliant = append(em.compliant, entry)
		}
	case configServiceTypes.ComplianceTypeNonCompliant:
		{
			em.nonCompliant = append(em.nonCompliant, entry)
		}
	case configServiceTypes.ComplianceTypeNotApplicable:
		{
			em.notApplicable = append(em.notApplicable, entry)
		}
	default:
		{
			log.Printf("unknown compliance type: [%s]\n", string(entry.ComplianceType))
			return errors.New("unknown compliance type" + "[" + string(entry.ComplianceType) + "]")
		}
	}
	return nil
}

// get entries
func (em *_EntryMgr) GetEntries(compliance string) ([]configServiceTypes.Evaluation, error) {
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
	case string(configServiceTypes.ComplianceTypeNotApplicable):
		{
			return em.notApplicable, nil
		}
	default:
		{
			log.Printf("unknown compliance type: [%s]\n", compliance)
			return nil, errors.New("unknown compliance type" + "[" + compliance + "]")
		}
	}
}
