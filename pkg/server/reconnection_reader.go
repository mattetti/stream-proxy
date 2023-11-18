package server

import (
	"io"
	"log"
	"net/http"
	"runtime/debug"
)

type reconnectingReader struct {
	req           *http.Request
	current       io.ReadCloser
	client        *http.Client
	reqID         string
	bytesRead     int64
	reconnects    int
	maxReconnects int
}

func (r *reconnectingReader) Read(p []byte) (n int, err error) {
	for {
		if r.current == nil {
			if r.reconnects >= r.maxReconnects {
				// Exceeded the maximum number of reconnection attempts
				log.Printf("[%s] Exceeded maximum number of reconnection attempts", r.reqID)
				return 0, io.EOF
			}

			resp, err := r.client.Do(r.req)
			if err != nil {
				r.reconnects++
				log.Printf("[%s] Error retrying connecting to remote: %s", r.reqID, err)
				continue // Retry the connection
			}
			log.Printf("[%s] Connected to remote", r.reqID)
			r.current = resp.Body
			r.reconnects = 0 // Reset reconnects counter on successful connection
		}

		n, err = r.current.Read(p)
		r.bytesRead += int64(n)

		if r.bytesRead >= 10*1024*1024 { // 10MB
			log.Printf("[%s] streamed %d bytes", r.reqID, r.bytesRead)
			r.bytesRead = 0 // Reset counter after logging
		}

		if err != nil {
			if err == io.EOF {
				r.current.Close()
				r.current = nil
				r.reconnects++
				log.Printf("[%s] Connection closed by remote - %d of %d [retrying]", r.reqID, r.reconnects, r.maxReconnects)
				continue // Attempt to reconnect
			}
			log.Printf("[%s] Error reading from connection: %s", r.reqID, err)
			return n, err
		}

		return n, nil
	}
}

func (r *reconnectingReader) Close() error {
	log.Printf("[%s] Closing connection = reconnectingReader.Close()", r.reqID)
	stack := string(debug.Stack())
	// if len(stack) > 300 {
	// 	stack = stack[:300]
	// }
	log.Printf("[%s] Stack: %s", r.reqID, stack)
	if r.current != nil {
		return r.current.Close()
	}
	return nil
}
