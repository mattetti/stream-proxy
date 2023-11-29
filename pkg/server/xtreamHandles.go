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
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"io"

	"github.com/gin-gonic/gin"
	"github.com/grafov/m3u8"
	"github.com/jamesnetherton/m3u"
	xtreamapi "github.com/pierre-emmanuelJ/iptv-proxy/pkg/xtream-proxy"
	uuid "github.com/satori/go.uuid"
)

type cacheMeta struct {
	string
	time.Time
}

//go:embed waiting_video.ts
var waitingVideo embed.FS

var hlsChannelsRedirectURL map[string]url.URL = map[string]url.URL{}
var hlsChannelsRedirectURLLock = sync.RWMutex{}

// XXX Use key/value storage e.g: etcd, redis...
// and remove that dirty globals
var xtreamM3uCache map[string]cacheMeta = map[string]cacheMeta{}
var xtreamM3uCacheLock = sync.RWMutex{}

func (c *Config) cacheXtreamM3u(playlist *m3u.Playlist, cacheName string) error {
	xtreamM3uCacheLock.Lock()
	defer xtreamM3uCacheLock.Unlock()

	tmp := *c
	tmp.playlist = playlist

	path := filepath.Join(os.TempDir(), uuid.NewV4().String()+".iptv-proxy.m3u")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := tmp.marshallInto(f, true); err != nil {
		return err
	}
	xtreamM3uCache[cacheName] = cacheMeta{path, time.Now()}

	return nil
}

func (c *Config) xtreamGenerateM3u(ctx *gin.Context, extension string) (*m3u.Playlist, error) {
	client, err := xtreamapi.New(c.XtreamUser.String(), c.XtreamPassword.String(), c.XtreamBaseURL, c.userAgent)
	if err != nil {
		return nil, err
	}
	client.HTTP = httpProxyClient

	cat, err := client.GetLiveCategories()
	if err != nil {
		return nil, err
	}

	// this is specific to xtream API,
	// prefix with "live" if there is an extension.
	var prefix string
	if extension != "" {
		extension = "." + extension
		prefix = "live/"
	}

	var playlist = new(m3u.Playlist)
	playlist.Tracks = make([]m3u.Track, 0)

	for _, category := range cat {
		live, err := client.GetLiveStreams(fmt.Sprint(category.ID))
		if err != nil {
			return nil, err
		}

		for _, stream := range live {
			track := m3u.Track{Name: stream.Name, Length: -1, URI: "", Tags: nil}

			//TODO: Add more tag if needed.
			if stream.EPGChannelID != "" {
				track.Tags = append(track.Tags, m3u.Tag{Name: "tvg-id", Value: stream.EPGChannelID})
			}
			if stream.Name != "" {
				track.Tags = append(track.Tags, m3u.Tag{Name: "tvg-name", Value: stream.Name})
			}
			if stream.Icon != "" {
				track.Tags = append(track.Tags, m3u.Tag{Name: "tvg-logo", Value: stream.Icon})
			}
			if category.Name != "" {
				track.Tags = append(track.Tags, m3u.Tag{Name: "group-title", Value: category.Name})
			}

			track.URI = fmt.Sprintf("%s/%s%s/%s/%s%s", c.XtreamBaseURL, prefix, c.XtreamUser, c.XtreamPassword, fmt.Sprint(stream.ID), extension)
			playlist.Tracks = append(playlist.Tracks, track)
		}
	}

	return playlist, nil
}

func (c *Config) xtreamGetAuto(ctx *gin.Context) {
	newQuery := ctx.Request.URL.Query()
	q := c.RemoteURL.Query()
	for k, v := range q {
		if k == "username" || k == "password" {
			continue
		}

		newQuery.Add(k, strings.Join(v, ","))
	}
	ctx.Request.URL.RawQuery = newQuery.Encode()
	ctx.Request.Header.Set("User-Agent", c.userAgent)

	c.xtreamGet(ctx)
}

func (c *Config) xtreamGet(ctx *gin.Context) {
	rawURL := fmt.Sprintf("%s/get.php?username=%s&password=%s", c.XtreamBaseURL, c.XtreamUser, c.XtreamPassword)

	q := ctx.Request.URL.Query()

	for k, v := range q {
		if k == "username" || k == "password" {
			continue
		}

		rawURL = fmt.Sprintf("%s&%s=%s", rawURL, k, strings.Join(v, ","))
	}

	m3uURL, err := url.Parse(rawURL)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	xtreamM3uCacheLock.RLock()
	meta, ok := xtreamM3uCache[m3uURL.String()]
	d := time.Since(meta.Time)
	if !ok || d.Hours() >= float64(c.M3UCacheExpiration) {
		log.Printf("[iptv-proxy] %v | %s | xtream cache m3u file\n", time.Now().Format("2006/01/02 - 15:04:05"), ctx.ClientIP())
		xtreamM3uCacheLock.RUnlock()
		playlist, err := m3u.Parse(m3uURL.String())
		if err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
			return
		}
		if err := c.cacheXtreamM3u(&playlist, m3uURL.String()); err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
			return
		}
	} else {
		xtreamM3uCacheLock.RUnlock()
	}

	ctx.Header("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, c.M3UFileName))
	xtreamM3uCacheLock.RLock()
	path := xtreamM3uCache[m3uURL.String()].string
	xtreamM3uCacheLock.RUnlock()
	ctx.Header("Content-Type", "application/octet-stream")

	ctx.File(path)
}

func (c *Config) xtreamApiGet(ctx *gin.Context) {
	const (
		apiGet = "apiget"
	)

	var (
		extension = ctx.Query("output")
		cacheName = apiGet + extension
	)

	xtreamM3uCacheLock.RLock()
	meta, ok := xtreamM3uCache[cacheName]
	d := time.Since(meta.Time)
	if !ok || d.Hours() >= float64(c.M3UCacheExpiration) {
		log.Printf("[iptv-proxy] %v | %s | xtream cache API m3u file\n", time.Now().Format("2006/01/02 - 15:04:05"), ctx.ClientIP())
		xtreamM3uCacheLock.RUnlock()
		playlist, err := c.xtreamGenerateM3u(ctx, extension)
		if err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
			return
		}
		if err := c.cacheXtreamM3u(playlist, cacheName); err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
			return
		}
	} else {
		xtreamM3uCacheLock.RUnlock()
	}

	ctx.Header("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, c.M3UFileName))
	xtreamM3uCacheLock.RLock()
	path := xtreamM3uCache[cacheName].string
	xtreamM3uCacheLock.RUnlock()
	ctx.Header("Content-Type", "application/octet-stream")

	ctx.File(path)

}

func (c *Config) xtreamPlayerAPIGET(ctx *gin.Context) {
	c.xtreamPlayerAPI(ctx, ctx.Request.URL.Query())
}

func (c *Config) xtreamPlayerAPIPOST(ctx *gin.Context) {
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

	c.xtreamPlayerAPI(ctx, q)
}

func (c *Config) xtreamPlayerAPI(ctx *gin.Context, q url.Values) {
	var action string
	if len(q["action"]) > 0 {
		action = q["action"][0]
	}

	client, err := xtreamapi.New(c.XtreamUser.String(), c.XtreamPassword.String(), c.XtreamBaseURL, ctx.Request.UserAgent())
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}
	client.HTTP = httpProxyClient

	isGuest, _ := ctx.Value("isGuest").(bool)
	resp, httpcode, err := client.Action(c.ProxyConfig, action, q, isGuest)
	if err != nil {
		ctx.AbortWithError(httpcode, err) // nolint: errcheck
		return
	}

	log.Printf("[iptv-proxy] %v | %s |Action\t%s\n", time.Now().Format("2006/01/02 - 15:04:05"), ctx.ClientIP(), action)

	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

func (c *Config) xtreamXMLTV(ctx *gin.Context) {
	client, err := xtreamapi.New(c.XtreamUser.String(), c.XtreamPassword.String(), c.XtreamBaseURL, ctx.Request.UserAgent())
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}
	client.HTTP = httpProxyClient

	resp, err := client.GetXMLTV()
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	ctx.Data(http.StatusOK, "application/xml", resp)
}

func (c *Config) xtreamStreamHandler(ctx *gin.Context) {
	id := ctx.Param("id")
	rpURL, err := url.Parse(fmt.Sprintf("%s/%s/%s/%s", c.XtreamBaseURL, c.XtreamUser, c.XtreamPassword, id))
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	c.xtreamStream(ctx, rpURL)
}

func (c *Config) xtreamStreamLive(ctx *gin.Context) {
	id := ctx.Param("id")
	rpURL, err := url.Parse(fmt.Sprintf("%s/live/%s/%s/%s", c.XtreamBaseURL, c.XtreamUser, c.XtreamPassword, id))
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	c.xtreamStream(ctx, rpURL)
}

func (c *Config) xtreamGuestStreamLive(ctx *gin.Context) {
	requestID, exists := ctx.Value("requestID").(string)
	if !exists {
		requestID = "unknown"
	}

	if !c.SharedStream.IsBeingUpdated() {
		// TODO: let the guest connect to whatever stream they want until the host
		// connects to a stream. Then, the guest should be redirected to the shared buffer.
		videoData, err := fs.ReadFile(waitingVideo, "waiting_video.ts")
		if err != nil {
			log.Printf("[%s] Failed to read embedded video: %v", requestID, err)
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		ctx.Writer.Header().Set("Content-Type", "video/MP2T")
		// Create a new reader for the video data
		videoReader := bytes.NewReader(videoData)

		for {
			// Stream the video content to the client using io.Copy
			n, err := io.Copy(ctx.Writer, videoReader)
			// log.Printf("[%s] Copied %d bytes to client", requestID, n)
			if n == 0 {
				log.Printf("[%s] No bytes copied to client, rewinding the waiting video", requestID)
				videoReader.Seek(0, io.SeekStart)
				continue
			}
			if err != nil {
				if err == io.EOF {
					log.Printf("[%s] Waiting video stream reached the end, rewinding", requestID)
					videoReader.Seek(0, io.SeekStart)
					continue
				}
				// Check for client disconnection
				if errors.Is(err, net.ErrClosed) {
					log.Printf("[%s] Connection closed by client: %v", requestID, err)
					return
				}

				log.Printf("[%s] Error during streaming: %v", requestID, err)
				ctx.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			// Flush the response if it supports flushing
			// if flusher, ok := ctx.Writer.(http.Flusher); ok {
			// 	flusher.Flush()
			// }
		}
	}

	c.SharedStream.AddClient()
	defer c.SharedStream.RemoveClient()

	_, streamErr := io.Copy(ctx.Writer, c.SharedStream)
	if streamErr != nil {
		ctx.AbortWithError(http.StatusInternalServerError, streamErr) // nolint: errcheck
		return
	}
}

func (c *Config) xtreamStreamPlay(ctx *gin.Context) {
	token := ctx.Param("token")
	t := ctx.Param("type")
	rpURL, err := url.Parse(fmt.Sprintf("%s/play/%s/%s", c.XtreamBaseURL, token, t))
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	c.xtreamStream(ctx, rpURL)
}

func (c *Config) xtreamStreamTimeshift(ctx *gin.Context) {
	duration := ctx.Param("duration")
	start := ctx.Param("start")
	id := ctx.Param("id")
	rpURL, err := url.Parse(fmt.Sprintf("%s/timeshift/%s/%s/%s/%s/%s", c.XtreamBaseURL, c.XtreamUser, c.XtreamPassword, duration, start, id))
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	c.stream(ctx, rpURL)
}

func (c *Config) xtreamStreamMovie(ctx *gin.Context) {
	id := ctx.Param("id")
	rpURL, err := url.Parse(fmt.Sprintf("%s/movie/%s/%s/%s", c.XtreamBaseURL, c.XtreamUser, c.XtreamPassword, id))
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	c.xtreamStream(ctx, rpURL)
}

func (c *Config) xtreamStreamSeries(ctx *gin.Context) {
	id := ctx.Param("id")
	rpURL, err := url.Parse(fmt.Sprintf("%s/series/%s/%s/%s", c.XtreamBaseURL, c.XtreamUser, c.XtreamPassword, id))
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	c.xtreamStream(ctx, rpURL)
}

func (c *Config) xtreamHlsStream(ctx *gin.Context) {
	chunk := ctx.Param("chunk")
	s := strings.Split(chunk, "_")
	if len(s) != 2 {
		ctx.AbortWithError( // nolint: errcheck
			http.StatusInternalServerError,
			errors.New("HSL malformed chunk"),
		)
		return
	}
	channel := s[0]

	url, err := getHlsRedirectURL(channel)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	req, err := url.Parse(
		fmt.Sprintf(
			"%s://%s/hls/%s/%s",
			url.Scheme,
			url.Host,
			ctx.Param("token"),
			ctx.Param("chunk"),
		),
	)

	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	c.xtreamStream(ctx, req)
}

func (c *Config) xtreamHlsrStream(ctx *gin.Context) {
	channel := ctx.Param("channel")

	url, err := getHlsRedirectURL(channel)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	req, err := url.Parse(
		fmt.Sprintf(
			"%s://%s/hlsr/%s/%s/%s/%s/%s/%s",
			url.Scheme,
			url.Host,
			ctx.Param("token"),
			c.XtreamUser,
			c.XtreamPassword,
			ctx.Param("channel"),
			ctx.Param("hash"),
			ctx.Param("chunk"),
		),
	)

	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err) // nolint: errcheck
		return
	}

	c.xtreamStream(ctx, req)
}

func getHlsRedirectURL(channel string) (*url.URL, error) {
	hlsChannelsRedirectURLLock.RLock()
	defer hlsChannelsRedirectURLLock.RUnlock()

	url, ok := hlsChannelsRedirectURL[channel+".m3u8"]
	if !ok {
		return nil, errors.New("HSL redirect url not found")
	}

	return &url, nil
}

func (c *Config) hlsXtreamStream(ctx *gin.Context, oriURL *url.URL) {
	requestID, exists := ctx.Value("requestID").(string)
	if !exists {
		requestID = "unknown"
	}

	// debugging:
	// Create a buffer to store the response body
	var bodyBuf bytes.Buffer

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
				redirectHost := location.Scheme + "://" + location.Host

				if redURL, err := url.Parse(redirectHost); err == nil {
					hlsPathKey := extractPath(location.String())
					log.Printf("[%s] Redirection key %s >> %s", requestID, hlsPathKey, redURL.String())
					// FIXME: we never clear the map memory
					hlsChannelsRedirectURLLock.RLock()
					hlsChannelsRedirectURL[hlsPathKey] = *redURL
					hlsChannelsRedirectURLLock.RUnlock()
				} else {
					log.Printf("[%s] Error parsing redirect host: %s", requestID, err.Error())
				}

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

			log.Printf("[%s] Manually Proxied URL: %s to %s completed with status code: %d", requestID, oriURL.String(), redirectURL, newResp.StatusCode)

			// debugging
			// Wrap the new response body with a TeeReader
			bodyBuf.Reset()
			teeReader := io.TeeReader(newResp.Body, &bodyBuf)
			// Set the TeeReader as the response body to be returned to the client
			resp.Body = io.NopCloser(teeReader)
			// resp.Body = newResp.Body
			resp.StatusCode = newResp.StatusCode
			resp.Header = newResp.Header

			// The body will be read and streamed back to the client when proxy.ServeHTTP is called
			// So you need to log the body after proxy.ServeHTTP, not here

			return nil
		}

		log.Printf("[%s] Proxied URL: %s completed with status code: %d", requestID, oriURL.String(), resp.StatusCode)
		return nil
	}

	proxy.Director = func(req *http.Request) {
		req.URL = oriURL
		req.Host = oriURL.Host
		req.Header = make(http.Header)
		mergeHttpHeader(req.Header, ctx.Request.Header)
		req.Header.Set("User-Agent", c.userAgent)
	}

	proxy.ServeHTTP(ctx.Writer, ctx.Request)
	if bodyBuf.Len() > 0 {
		// Log the body
		// log.Printf("[%s] Response body: %s", requestID, bodyBuf.String())
		// parseHLSM3u8Body(&bodyBuf, requestID)
	}
}

// xtreamHlsNginxHandler proxies the request to the URL defined in hlsChannelsRedirectURL
func (c *Config) xtreamHlsNginxHandler(ctx *gin.Context) {
	requestID, exists := ctx.Value("requestID").(string)
	if !exists {
		requestID = "unknown"
	}
	// log.Printf("Incoming request: %s", ctx.Request.URL.String())

	// Extract the original request URL from the Gin context
	originalReq := ctx.Request

	// Use the URL from the original request to get the path and query
	originalPath := originalReq.URL.Path
	originalQuery := originalReq.URL.RawQuery

	// Log the original path and query
	// log.Printf("Original path: %s, query: %s", originalPath, originalQuery)

	// Look up the redirect URL
	hlsPathKey := extractPath(originalPath)
	hlsChannelsRedirectURLLock.RLock()
	oriURL, ok := hlsChannelsRedirectURL[hlsPathKey]
	hlsChannelsRedirectURLLock.RUnlock()

	if !ok {
		log.Printf("[%s] URL not found in hlsChannelsRedirectURL for path: %s", requestID, hlsPathKey)
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "URL not found"})
		return
	}

	// Append query parameters to the original URL
	if len(originalQuery) > 0 {
		oriURL.Path = originalPath
		oriURL.RawQuery = originalQuery
	}

	// Log the final URL to be proxied
	// log.Printf("Proxied URL: %s", oriURL.String())

	// Set up the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(&oriURL)

	// Update the request URL for the proxy
	proxy.Director = func(req *http.Request) {
		req.URL = &oriURL
		req.Host = oriURL.Host
		req.Header = make(http.Header)
		mergeHttpHeader(req.Header, ctx.Request.Header)
		req.Header.Set("User-Agent", c.userAgent)
	}

	// Handle proxy errors
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
		log.Printf("[%s] Error proxying request to %s: %v", requestID, oriURL.String(), err)
		ctx.AbortWithError(http.StatusInternalServerError, err)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode == http.StatusForbidden {
			// TODO: consider a retry using the original URL before the redirect
			log.Printf("[%s] Forbidden URL: %s - %s", requestID, oriURL.String(), ctx.ClientIP())
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden URL"})
			return nil
		}
		return nil
	}

	// Serve the proxy
	proxy.ServeHTTP(ctx.Writer, ctx.Request)

	// Log the end of the request
	// log.Printf("Proxy request completed for: %s", ctx.Request.URL.String())
}

func extractPath(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		log.Printf("Error parsing URL: %s", err.Error())
		return "/play/hls-nginx/" // Fallback key
	}

	// Check if the path ends with .m3u8
	if strings.HasSuffix(parsedURL.Path, ".m3u8") {
		_, file := path.Split(parsedURL.Path)
		return strings.TrimSuffix(file, ".m3u8") // Return filename without .m3u8
	}

	// If the path ends with .ts
	if strings.HasSuffix(parsedURL.Path, ".ts") {
		// Extract the segment after /play/hls-nginx/
		trimmedPath := strings.TrimPrefix(parsedURL.Path, "/play/hls-nginx/")
		segments := strings.Split(trimmedPath, "/")
		if len(segments) > 0 {
			return segments[0] // Return the first segment
		}
	}

	return parsedURL.Path
}

func parseHLSM3u8Body(bodyBuf *bytes.Buffer, requestID string) {
	// Create a reader from the buffer
	bufReader := bytes.NewReader(bodyBuf.Bytes())

	// Use the m3u8 library to parse the playlist
	playlist, listType, err := m3u8.DecodeFrom(bufReader, true)
	if err != nil {
		log.Printf("[%s] Error parsing m3u8: %s", requestID, err)
		return
	}

	switch listType {
	case m3u8.MEDIA:
		mediaPlaylist := playlist.(*m3u8.MediaPlaylist)
		// Iterate over segments and extract URLs
		for _, segment := range mediaPlaylist.Segments {
			if segment != nil {
				log.Printf("[%s] Segment URL: %s", requestID, segment.URI)
			}
		}

	case m3u8.MASTER:
		masterPlaylist := playlist.(*m3u8.MasterPlaylist)
		// Iterate over variants and extract URLs
		for _, variant := range masterPlaylist.Variants {
			if variant != nil {
				log.Printf("[%s] Variant URL: %s", requestID, variant.URI)
			}
		}
	}
}
