package worker

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/outofoffice3/policy-general/internal/iampolicyevaluator"
)

type ComplianceWorker struct {
	ctx       context.Context
	id        string
	errorChan chan error
	request   chan ComplianceWorkerRequest
}

type ComplianceWorkerInput struct {
	Ctx       context.Context
	Id        string
	ErrorChan chan error
	Result    chan ComplianceWorkerRequest
}

type ComplianceWorkerRequest struct {
	IAMIdentity          IAMIdentity
	IamClient            *iam.Client
	AccessAnalyzerClient *accessanalyzer.Client
	IamPolicyEvaluator   iampolicyevaluator.IAMPolicyEvaluator
}

type IAMIdentity struct {
	Role iamTypes.Role
	User iamTypes.User
}

func NewRoleWorker(input ComplianceWorker) Worker {
	return &ComplianceWorker{
		ctx:       input.ctx,
		id:        input.id,
		errorChan: input.errorChan,
		request:   input.request,
	}
}

func (r *ComplianceWorker) Run() {
	for {
		select {
		case req := <-r.request:
			{
				log.Printf("Worker %s received request [%v]\n", r.id, req)
			}

		case <-r.ctx.Done():
			{
				return
			}

		}
	}
}
