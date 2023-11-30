package server

import (
	"io"
	"log"
	"sync"
	"time"
)

const ringBufferSize = 1024 * 1024 * 10 // 10MB

type RingBufferReader struct {
	readPos        int
	bufferedStream *BufferedStream
}

func (r *RingBufferReader) Read(p []byte) (n int, err error) {
	return r.bufferedStream.Read(r, p)
}

type ringBuffer struct {
	data     []byte
	size     int
	start    int
	length   int
	writePos int
	mu       sync.RWMutex
}

func newRingBuffer(size int) *ringBuffer {
	return &ringBuffer{
		data: make([]byte, size),
		size: size,
	}
}

func (rb *ringBuffer) Write(p []byte) (n int, err error) {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	// initialWritePos := rb.writePos
	for _, b := range p {
		rb.data[rb.writePos] = b
		rb.writePos = (rb.writePos + 1) % rb.size
		if rb.length < rb.size {
			rb.length++
		} else {
			rb.start = (rb.start + 1) % rb.size
		}
	}
	// log.Printf("Wrote %d bytes to buffer. WritePos moved from %d to %d\n", len(p), initialWritePos, rb.writePos)

	return len(p), nil
}

func (rb *ringBuffer) ReadFromLast(p []byte) (n int, err error) {
	if rb.length == 0 {
		return 0, nil // or io.EOF if you prefer
	}

	readPos := (rb.start + rb.length - len(p)) % rb.size
	if readPos < 0 {
		readPos += rb.size
	}

	for i := 0; i < len(p) && i < rb.length; i++ {
		p[i] = rb.data[(readPos+i)%rb.size]
	}
	return min(len(p), rb.length), nil
}

func (rb *ringBuffer) Read(p []byte) (n int, err error) {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.length == 0 {
		return 0, io.EOF
		// No data available right now, return 0 and no error.
		// io.Copy will continue calling Read.
		// log.Println("No data available to read, returning 0 bytes")
		// return 0, nil
	}

	for i := 0; i < len(p); i++ {
		if i >= rb.length {
			// We've read all available data.
			break
		}
		p[i] = rb.data[(rb.start+i)%rb.size]
		rb.start = (rb.start + 1) % rb.size
		rb.length--
		n++
	}

	return n, nil
}

func (rb *ringBuffer) Bytes() []byte {
	bytes := make([]byte, rb.length)
	for i := 0; i < rb.length; i++ {
		bytes[i] = rb.data[(rb.start+i)%rb.size]
	}
	return bytes
}

func (rb *ringBuffer) Reset() {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.start = 0
	rb.length = 0
	rb.writePos = 0
	log.Println("Buffer reset")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

//---------------------------------------------

type BufferedStream struct {
	writingActive bool
	mu            sync.RWMutex
	buffer        *ringBuffer
	readers       map[*RingBufferReader]struct{}
	active        bool
	clientCount   int
	writeTimer    *time.Timer
	writeDelay    time.Duration
}

func NewBufferedStream() *BufferedStream {
	return &BufferedStream{
		buffer:     newRingBuffer(ringBufferSize),
		active:     false,
		readers:    make(map[*RingBufferReader]struct{}),
		writeDelay: 30 * time.Second,
	}
}

func (bs *BufferedStream) NewReader() *RingBufferReader {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	reader := &RingBufferReader{
		readPos:        0, // Initialize the reader with the start position
		bufferedStream: bs,
	}
	bs.readers[reader] = struct{}{}
	log.Printf("New reader %p created", reader)
	return reader
}

func (bs *BufferedStream) RemoveReader(reader *RingBufferReader) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	delete(bs.readers, reader)
	log.Printf("Reader %p removed", reader)
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
	return bs.buffer.Write(p) // always write to the buffer
}

func (bs *BufferedStream) Read(reader *RingBufferReader, p []byte) (n int, err error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	if bs.buffer.length == 0 {
		// Reader has caught up with the writer, no more data to read
		return 0, io.EOF
	}
	// initialReadPos := reader.readPos
	for i := range p {
		if reader.readPos == bs.buffer.writePos {
			// Reader has caught up with the writer, no more data to read
			break
		}

		p[i] = bs.buffer.data[reader.readPos]
		reader.readPos = (reader.readPos + 1) % bs.buffer.size
		n++
	}

	// log.Printf("Reader %p read %d bytes from buffer. ReadPos moved from %d to %d\n", reader, n, initialReadPos, reader.readPos)

	return n, nil
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
