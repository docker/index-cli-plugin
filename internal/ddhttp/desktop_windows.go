package ddhttp

import (
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

func dialDesktopHTTPProxy() (net.Conn, error) {
	timeout := time.Second
	return winio.DialPipe(`\\.\pipe\dockerHTTPProxy`, &timeout)
}
