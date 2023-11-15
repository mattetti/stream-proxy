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
	log.SetOutput(gin.DefaultWriter)

	requestID, exists := ctx.Value("requestID").(string)
	if !exists {
		requestID = "unknown"
	}
	log.Printf("[%s] >> reverse proxy streaming: %s", requestID, oriURL.String())

	defer func() {
		if r := recover(); r != nil {
			log.Printf("[%s] >> reverse proxy panic recovered: %v\n", requestID, r)
			// debug.PrintStack()

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
				// Record redirect hosts for /play/hls/*
				// redirectHost := location.Scheme + "://" + location.Host

				log.Printf("[%s] Redirected from %s to %s", requestID, oriURL.String(), redirectURL)
				// if redURL, err := url.Parse(redirectHost); err == nil {
				// 	hlsChannelsRedirectURL["/play/hls-nginx/"] = *redURL
				// } else {
				// 	log.Printf("Error parsing redirect host: %s", err.Error())
				// }

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
		requestID, _ := r.Context().Value("requestID").(string)
		log.Printf("[%s] Error during proxying the request: %v, URL: %s", requestID, err, r.URL.String())

		// You can send a custom error response to the client
		http.Error(w, "An error occurred while processing your request.", http.StatusBadGateway)
	}

	proxy.ServeHTTP(ctx.Writer, ctx.Request)
}

func (c *Config) Oldstream(ctx *gin.Context, oriURL *url.URL) {

	requestID, exists := ctx.Value("requestID").(string)
	if !exists {
		requestID = "unknown"
	}
	log.Printf("[%s] >> reverse proxy streaming: %s", requestID, oriURL.String())

	req, err := http.NewRequest("GET", oriURL.String(), nil)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	mergeHttpHeader(req.Header, ctx.Request.Header)
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := httpProxyClient.Do(req)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}
	defer resp.Body.Close()

	mergeHttpHeader(ctx.Writer.Header(), resp.Header)
	ctx.Status(resp.StatusCode)
	ctx.Stream(func(w io.Writer) bool {
		io.Copy(w, resp.Body) // nolint: errcheck
		return false
	})
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
