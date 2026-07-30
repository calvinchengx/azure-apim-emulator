// Package clock provides the emulator's controllable time source.
package clock

import (
	"sync"
	"time"
)

// Clock is a concurrency-safe, offsettable, freezable clock.
type Clock struct {
	mu       sync.RWMutex
	offset   int64
	frozen   bool
	frozenAt int64
	realNow  func() int64
}

// New returns a clock tracking wall time.
func New() *Clock {
	return &Clock{realNow: func() int64 { return time.Now().Unix() }}
}

// Now returns controlled epoch seconds.
func (c *Clock) Now() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.frozen {
		return c.frozenAt
	}
	return c.realNow() + c.offset
}

// Advance moves controlled time by seconds.
func (c *Clock) Advance(seconds int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.frozen {
		c.frozenAt += seconds
	} else {
		c.offset += seconds
	}
}

// SetOffset sets the wall-clock offset and unfreezes time.
func (c *Clock) SetOffset(seconds int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset = seconds
	c.frozen = false
}

// Freeze pins the current controlled time.
func (c *Clock) Freeze() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.frozen {
		c.frozenAt = c.realNow() + c.offset
		c.frozen = true
	}
}

// Unfreeze resumes wall-clock progression without jumping.
func (c *Clock) Unfreeze() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.frozen {
		c.offset = c.frozenAt - c.realNow()
		c.frozen = false
	}
}

// State returns offset, frozen state, and current epoch seconds.
func (c *Clock) State() (int64, bool, int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.frozen {
		return c.frozenAt - c.realNow(), true, c.frozenAt
	}
	return c.offset, false, c.realNow() + c.offset
}
