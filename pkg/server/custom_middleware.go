package server

import (
	"log"

	"github.com/gin-gonic/gin"
)

func IncomingRequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		userAgent := c.Request.UserAgent()

		// Truncate userAgent if necessary
		if len(userAgent) > 70 {
			userAgent = userAgent[:70] + "..."
		}
		// Log using the same writer as Gin's default logger
		log.SetOutput(gin.DefaultWriter)
		log.Printf("[incoming] %s - %s %s | %s\n",
			c.ClientIP(),
			c.Request.Method,
			c.Request.URL.Path,
			userAgent,
		)

		c.Next()
	}
}
