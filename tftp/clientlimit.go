package tftp

import (
	"errors"
	"sync"
)

type Clientlimit struct {
	mu         sync.Mutex
	numClients int
	maxClients int
}

func (c *Clientlimit) increaseClientCount() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	newClientNum := c.numClients + 1
	if newClientNum > c.maxClients {
		return errors.New("Error")
	}
	c.numClients = newClientNum
	return nil
}

func (c *Clientlimit) decreaseClientCount() {
	c.mu.Lock()
	defer c.mu.Unlock()
	newClientNum := c.numClients - 1
	if newClientNum < 0 {
		//TODO real error handling
		panic("Current client count went under 0")
	}
	c.numClients = newClientNum
}

func NewClientLimit(clients int) *Clientlimit {
	return &Clientlimit{
		mu:         sync.Mutex{},
		numClients: 0,
		maxClients: clients,
	}
}
