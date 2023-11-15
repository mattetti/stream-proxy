/*
 * Iptv-Proxy is a project to proxyfie an m3u file and to proxyfie an Xtream iptv service (client API).
 * Copyright (C) 2020  Pierre-Emmanuel Jacquier
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package server

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func (c *Config) getM3U(ctx *gin.Context) {
	ctx.Header("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, c.M3UFileName))
	ctx.Header("Content-Type", "application/octet-stream")

	ctx.File(c.proxyfiedM3UPath)
}

func (c *Config) reverseProxy(ctx *gin.Context) {
	rpURL, err := url.Parse(c.track.URI)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	c.stream(ctx, rpURL)
}

func (c *Config) m3u8ReverseProxy(ctx *gin.Context) {
	id := ctx.Param("id")

	rpURL, err := url.Parse(strings.ReplaceAll(c.track.URI, path.Base(c.track.URI), id))
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	c.stream(ctx, rpURL)
}

func (c *Config) stream(ctx *gin.Context, oriURL *url.URL) {
	requestID, exists := ctx.Value("requestID").(string)
	if !exists {
		requestID = "unknown"
	}
	proxiedURL := oriURL.String()
	if len(proxiedURL) > 70 {
		proxiedURL = proxiedURL[:70] + "..."
	}
	log.Printf("[%s] (proxy streaming) %s - %s", requestID, proxiedURL, ctx.ClientIP())

	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok {
				if err == http.ErrAbortHandler {
					// Handle the specific case of http.ErrAbortHandler
					log.Printf("[%s] (client disconnected) %v, URL: %s", requestID, err, oriURL.String())
					ctx.AbortWithStatus(http.StatusOK)
				} else {
					// Handle other error types
					log.Printf("[%s] >> reverse proxy panic recovered: %v\n", requestID, err)
				}
			} else {
				// r is not an error type
				log.Printf("[%s] >> reverse proxy panic recovered: unknown type: %v\n", requestID, r)
			}

			// Respond with an error or take other appropriate actions
			// ctx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("internal server error"))
			ctx.AbortWithStatus(http.StatusOK)
		}
	}()

	proxy := httputil.NewSingleHostReverseProxy(oriURL)
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode == http.StatusFound {
			location, err := resp.Location()
			if err != nil {
				return err
			}

			redirectURL := location.String()
			if !location.IsAbs() {
				// If the Location is relative, construct the absolute URL
				redirectURL = oriURL.ResolveReference(location).String()
			} else {

				logRedirectURL := redirectURL
				if len(logRedirectURL) > 70 {
					logRedirectURL = logRedirectURL[:70] + "..."
				}

				log.Printf("[%s] (302) from %s to %s - %s", requestID, oriURL.String(), logRedirectURL, ctx.ClientIP())
			}

			// log.Printf("Redirected from %s to %s", oriURL.String(), redirectURL)

			// Create a new request for the redirect location
			newReq, err := http.NewRequest("GET", redirectURL, nil)
			if err != nil {
				return err
			}

			// Copy the headers from the original request
			for headerName, values := range ctx.Request.Header {
				for _, value := range values {
					newReq.Header.Add(headerName, value)
				}
			}
			newReq.Header.Set("User-Agent", c.userAgent)

			// Preserve query parameters
			q := location.Query()
			for param, values := range q {
				for _, value := range values {
					newReq.URL.Query().Add(param, value)
				}
			}

			// Send the new request and stream the response
			newResp, err := httpProxyClient.Do(newReq)
			if err != nil {
				return err
			}

			resp.Body = newResp.Body
			resp.StatusCode = newResp.StatusCode
			resp.Header = newResp.Header

			return nil
		}

		log.Printf("Proxied URL: %s completed with status code: %d", oriURL.String(), resp.StatusCode)
		return nil
	}

	proxy.Director = func(req *http.Request) {
		req.URL = oriURL
		req.Host = oriURL.Host
		req.Header = make(http.Header)
		mergeHttpHeader(req.Header, ctx.Request.Header)
		req.Header.Set("User-Agent", c.userAgent)
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if strings.Contains(err.Error(), "context canceled") {
			log.Printf("[%s] (client disconnected) %v, URL: %s", requestID, err, r.URL.String())
			return
		}
		// requestID, _ := r.Context().Value("requestID").(string)
		log.Printf("[%s] (Error proxying) %v, URL: %s", requestID, err, r.URL.String())

		// You can send a custom error response to the client
		http.Error(w, "An error occurred while processing your request.", http.StatusBadGateway)
	}

	proxy.ServeHTTP(ctx.Writer, ctx.Request)
}

func (c *Config) xtreamStream(ctx *gin.Context, oriURL *url.URL) {
	id := ctx.Param("id")
	if strings.HasSuffix(id, ".m3u8") {
		c.hlsXtreamStream(ctx, oriURL)
		return
	}

	c.stream(ctx, oriURL)
}

type values []string

func (vs values) contains(s string) bool {
	for _, v := range vs {
		if v == s {
			return true
		}
	}

	return false
}

func mergeHttpHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			if values(dst.Values(k)).contains(v) {
				continue
			}
			dst.Add(k, v)
		}
	}
}

// authRequest handle auth credentials
type authRequest struct {
	Username string `form:"username" binding:"required"`
	Password string `form:"password" binding:"required"`
}

func (c *Config) authenticate(ctx *gin.Context) {
	var authReq authRequest
	if err := ctx.Bind(&authReq); err != nil {
		ctx.AbortWithError(http.StatusBadRequest, err) // nolint: errcheck
		return
	}
	if c.ProxyConfig.User.String() != authReq.Username || c.ProxyConfig.Password.String() != authReq.Password {
		ctx.AbortWithStatus(http.StatusUnauthorized)
	}
}

func (c *Config) appAuthenticate(ctx *gin.Context) {
	contents, err := io.ReadAll(io.Reader(ctx.Request.Body))
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	q, err := url.ParseQuery(string(contents))
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}
	if len(q["username"]) == 0 || len(q["password"]) == 0 {
		ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("bad body url query parameters")) // nolint: errcheck
		return
	}
	log.Printf("[iptv-proxy] %v | %s |App Auth\n", time.Now().Format("2006/01/02 - 15:04:05"), ctx.ClientIP())
	if c.ProxyConfig.User.String() != q["username"][0] || c.ProxyConfig.Password.String() != q["password"][0] {
		ctx.AbortWithStatus(http.StatusUnauthorized)
	}

	ctx.Request.Body = io.NopCloser(io.Reader(bytes.NewReader(contents)))
}
