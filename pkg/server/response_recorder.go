package server

import (
	"bytes"
	"fmt"

	"github.com/gin-gonic/gin"
)

type responseRecorder struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (r *responseRecorder) WriteHeader(code int) {
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

func responseBodyLoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		rec := &responseRecorder{body: &bytes.Buffer{}, ResponseWriter: c.Writer}
		c.Writer = rec

		c.Next()

		// Log status code and response
		statusCode := c.Writer.Status()
		responseBody := rec.body.String()
		// Log status code
		fmt.Printf("Status code: %d\n", statusCode)

		// Log response body
		fmt.Printf("Response body: %s\n", responseBody)
	}
}
