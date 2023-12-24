package worker

type Worker interface {
	// start execution for worker
	Run()
}

type _Worker struct {
	id int
}

func NewWorker(id int) Worker {
	return &_Worker{
		id: id,
	}
}

func (w *_Worker) Run() {

}
