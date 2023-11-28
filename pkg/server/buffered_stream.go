package server

import (
	"bytes"
	"sync"
	"time"
)

type BufferedStream struct {
	writingActive bool
	mu            sync.RWMutex
	buffer        *bytes.Buffer
	active        bool
	clientCount   int
	writeTimer    *time.Timer
	writeDelay    time.Duration
}

func NewBufferedStream() *BufferedStream {
	return &BufferedStream{
		buffer:     new(bytes.Buffer),
		active:     false,
		writeDelay: 30 * time.Second,
	}
}

func (bs *BufferedStream) Write(p []byte) (n int, err error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// Reset the timer on each write
	if bs.writeTimer != nil {
		bs.writeTimer.Stop()
	}
	bs.writeTimer = time.AfterFunc(bs.writeDelay, func() {
		bs.mu.Lock()
		bs.writingActive = false
		bs.mu.Unlock()
	})

	bs.writingActive = true
	if bs.active {
		return bs.buffer.Write(p)
	}
	return len(p), nil // if not active, pretend to write
}

func (bs *BufferedStream) Read(p []byte) (n int, err error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.buffer.Read(p)
}

func (bs *BufferedStream) SetActive(active bool) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.active = active
}

func (bs *BufferedStream) Reset() {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.buffer.Reset()
}

func (bs *BufferedStream) ReadBuffer() []byte {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.buffer.Bytes()
}

func (bs *BufferedStream) AddClient() {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.clientCount == 0 {
		bs.active = true
	}
	bs.clientCount++
}

func (bs *BufferedStream) RemoveClient() {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.clientCount--
	if bs.clientCount == 0 {
		bs.active = false
		bs.buffer.Reset()
	}
}

func (bs *BufferedStream) IsActive() bool {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.active
}

// IsBeingUpdated returns true if the host is currently written to
func (bs *BufferedStream) IsBeingUpdated() bool {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.writingActive
}
