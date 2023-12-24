package worker

import (
	"context"
	"log"
	"sync"

	"github.com/outofoffice3/policy-general/internal/writer"
)

type ErrorWorker struct {
	ctx       context.Context
	wg        *sync.WaitGroup
	id        int
	errorChan chan error
	writer    writer.Writer
}

type ErrorWorkerInput struct {
	Ctx       context.Context
	Wg        *sync.WaitGroup
	Id        int
	ErrorChan chan error
	Writer    writer.Writer
}

func NewErrorWorker(input ErrorWorkerInput) Worker {
	return &ErrorWorker{
		ctx:       input.Ctx,
		wg:        input.Wg,
		id:        input.Id,
		errorChan: input.ErrorChan,
		writer:    input.Writer,
	}
}

func (w *ErrorWorker) Run() {
	defer w.wg.Done()
	var (
		batch     []error
		header    []string
		csvErrors [][]string
	)
	csvErrors = [][]string{}
	batch = []error{}
	for {
		select {
		case err := <-w.errorChan:
			{
				batch = append(batch, err)

			}
		case <-w.ctx.Done():
			{
				log.Printf("error worker %d received context cancellation", w.id)

				// write errors to csvErrors[][]string
				for _, err := range batch {
					csvErrors = append(csvErrors, []string{err.Error()})
				}

				// write to csv
				header = []string{"error"}
				result, err := w.writer.WriteCSV("errors.txt", header, csvErrors)
				if err != nil {
					log.Printf("error worker %d failed to write errors to csv: %v", w.id, err)
				}
				log.Printf("error worker %d wrote errors to file: %v", w.id, result)
			}
		}
	}

}
