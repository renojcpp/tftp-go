package tftp

type Semaphore struct {
	ch chan struct{}
}

func NewSemaphore(numOfClients int) *Semaphore {
	return &Semaphore{
		ch: make(chan struct{}, numOfClients),
	}
}

func (s *Semaphore) Acquire() {
	s.ch <- struct{}{}

}
func (s *Semaphore) Release() {
	<-s.ch
}
