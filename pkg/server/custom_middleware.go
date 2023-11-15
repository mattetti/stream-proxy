package server

import (
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
)

func IncomingRequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := uuid.NewV4().String()[:7]
		// Set the request ID in the context
		c.Set("requestID", requestID)

		userAgent := c.Request.UserAgent()

		// Truncate userAgent if necessary
		if len(userAgent) > 70 {
			userAgent = userAgent[:70] + "..."
		}
		// Log using the same writer as Gin's default logger
		log.SetOutput(gin.DefaultWriter)
		log.Printf("[in]  %s %s - %s %s | %s\n",
			requestID,
			c.ClientIP(),
			c.Request.Method,
			c.Request.URL.Path,
			userAgent,
		)

		c.Next()

		statusCode := 199
		if c.Request.Response != nil {
			statusCode = c.Request.Response.StatusCode
		}

		log.Printf("[out] %s %d - %s - %s %s | %s\n",
			requestID,
			statusCode,
			c.ClientIP(),
			c.Request.Method,
			c.Request.URL.Path,
			userAgent,
		)
	}
}

func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate a unique request ID
		requestID := uuid.NewV4().String()
		// Set the request ID in the context
		c.Set("requestID", requestID)

		c.Next()
	}
}

func LoggerWithRequestID() gin.HandlerFunc {
	formatter := func(param gin.LogFormatterParams) string {
		// Retrieve the request ID from the context
		requestID, exists := param.Request.Context().Value("requestID").(string)
		if !exists {
			requestID = "unknown"
		}

		return fmt.Sprintf("[%s] - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.TimeStamp.Format(time.RFC3339),
			requestID,
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.ClientIP,
			param.ErrorMessage,
		)
	}

	return gin.LoggerWithFormatter(formatter)
}
