package ddhttp

import (
	"context"
	"net"
	"net/http"
	"net/url"
)

var transport http.RoundTripper

func init() {
	// Check if we can discuss with the proxy socket from Docker Desktop.
	// If we can, it doesn't necessarily mean there a configured proxy.
	// But we delegate that management to Docker Desktop: if the socket is open, we connect to it. Docker Desktop can
	// then send the requests to a proxy or not, but that's Docker Desktop scope.
	// If we can't connect to the socket, then just use plain default transport.
	if !isDesktopHTTPProxyAvailable() {
		transport = http.DefaultTransport
		return
	}

	transport = &http.Transport{
		Proxy: http.ProxyURL(&url.URL{
			Scheme: "http",
		}),
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return dialDesktopHTTPProxy()
		},
	}
}

func isDesktopHTTPProxyAvailable() bool {
	c, err := dialDesktopHTTPProxy()
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func DefaultClient() *http.Client {
	return &http.Client{
		Transport: transport,
	}
}

func DefaultTransport() *http.Transport {
	if t, ok := transport.(*http.Transport); ok {
		return t
	}
	panic("could not get transport")
}
