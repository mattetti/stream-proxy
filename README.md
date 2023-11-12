# Iptv Proxy

[![Actions Status](https://github.com/pierre-emmanuelJ/iptv-proxy/workflows/CI/badge.svg)](https://github.com/pierre-emmanuelJ/iptv-proxy/actions?query=workflow%3ACI)

## Description

Iptv-Proxy is a project to proxyfie an Xtream iptv service (client API).

(This fork focuses on making the xtream-code proxying working but YMMV, no support provided, I forked/patched to help someone)


### Xtream code client api

proxy on Xtream code (client API)

support live, vod, series and full epg :rocket:


### Xtream code client API example

```Bash
% iptv-proxy --m3u-url http://example.com:1234/get.php?username=user&password=pass&type=m3u_plus&output=m3u8 \
             --port 8080 \
             --hostname proxyexample.com \
             ## put xtream flags to activate the xtream proxy
             --xtream-user xtream_user \
             --xtream-password xtream_password \
             --xtream-base-url http://example.com:1234 \
             --user test \
             --password passwordtest
             
```

What Xtream proxy do

 - swap the proxy `user` and `password` for the xtream `xtream-user ` and `xtream-password` and proxies the requests.
 - swap the proxy `hostname` and `port` for `xtream-base-url`
 - reverse proxy streams (without buffering server side)
 
Original xtream credentials
 
 ```
 user: xtream_user
 password: xtream_password
 base-url: http://example.com:1234
 ```
 
New xtream credentials

 ```
 user: test
 password: passwordtest
 base-url: http://proxyexample.com:8080
 ```
 
 All xtream live, streams, vod, series... are proxyfied! 
 
 
 You can get the m3u file with the original Xtream api request:
 ```
 http://proxyexample.com:8080/get.php?username=test&password=passwordtest&type=m3u_plus&output=ts
 ```


## Installation

Download lasted [release](https://github.com/pierre-emmanuelJ/iptv-proxy/releases)

Or

`% go install` in root repository

## With Docker

### Prerequisite

 - Add an m3u URL in `docker-compose.yml` or add local file in `iptv` folder
 - `HOSTNAME` and `PORT` to expose
 - Expose same container port as the `PORT` ENV variable 

```Yaml
 ports:
       # have to be the same as ENV variable PORT
      - 8080:8080
 environment:
      # if you are using m3u remote file
      # M3U_URL: http://example.com:1234/get.php?username=user&password=pass&type=m3u_plus&output=m3u8
      M3U_URL: /root/iptv/iptv.m3u
      # Port to expose the IPTVs endpoints
      PORT: 8080
      # Hostname or IP to expose the IPTVs endpoints (for machine not for docker)
      HOSTNAME: localhost
      GIN_MODE: release
      ## Xtream-code proxy configuration
      ## (put these env variables if you want to add xtream proxy)
      XTREAM_USER: xtream_user
      XTREAM_PASSWORD: xtream_password
      XTREAM_BASE_URL: "http://example.com:1234"
      USER: test
      PASSWORD: testpassword
```

### Start

```
% docker-compose up -d
```

## TLS - https with traefik

Put files and folders of `./traekik` folder in root repo:
```Shell
$ cp -r ./traekik/* .
```

```Shell
$ mkdir config \
        && mkdir -p Traefik/etc/traefik \
        && mkdir -p Traefik/log
```


`docker-compose` sample with traefik:
```Yaml
version: "3"
services:
  iptv-proxy:
    build:
      context: .
      dockerfile: Dockerfile
    volumes:
      # If your are using local m3u file instead of m3u remote file
      # put your m3u file in this folder
      - ./iptv:/root/iptv
    container_name: "iptv-proxy"
    restart: on-failure
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.iptv-proxy.rule=Host(`iptv.proxyexample.xyz`)"
      - "traefik.http.routers.iptv-proxy.entrypoints=websecure"
      - "traefik.http.routers.iptv-proxy.tls.certresolver=mydnschallenge"
      - "traefik.http.services.iptv-proxy.loadbalancer.server.port=8080"
    environment:
      # if you are using m3u remote file
      # M3U_URL: https://example.com/iptvfile.m3u
      M3U_URL: /root/iptv/iptv.m3u
      # Iptv-Proxy listening port
      PORT: 8080
      # Port to expose for Xtream or m3u file tracks endpoint
      ADVERTISED_PORT: 443
      # Hostname or IP to expose the IPTVs endpoints (for machine not for docker)
      HOSTNAME: iptv.proxyexample.xyz
      GIN_MODE: release
      # Inportant to activate https protocol on proxy links
      HTTPS: 1
      ## Xtream-code proxy configuration
      XTREAM_USER: xtream_user
      XTREAM_PASSWORD: xtream_password
      XTREAM_BASE_URL: "http://example.tv:1234"
      #will be used for m3u and xtream auth proxy
      USER: test
      PASSWORD: testpassword

  traefik:
    restart: always
    image: traefik:v2.4
    read_only: true
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./Traefik/traefik.yaml:/traefik.yaml:ro
      - ./Traefik/etc/traefik:/etc/traefik/
      - ./Traefik/log:/var/log/traefik/
```

Replace `iptv.proxyexample.xyz` in `docker-compose.yml` with your desired domain.

```Shell
$ docker-compose up -d
```

## TODO

there is basic auth just for testing.
change with a real auth with database and user management
and auth with token...

**ENJOY!**

## Powered by

- [cobra](https://github.com/spf13/cobra)
- [go.xtream-codes](https://github.com/tellytv/go.xtream-codes)
- [gin](https://github.com/gin-gonic/gin)

Grab me a beer 🍻

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif)](https://www.paypal.com/donate?hosted_button_id=WQAAMQWJPKHUN)

