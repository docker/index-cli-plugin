package ddhttp

import (
	"net"
	"os/user"
	"path"
)

func dialDesktopHTTPProxy() (net.Conn, error) {
	current, err := user.Current()
	if err != nil {
		return nil, err
	}
	socket := path.Join(current.HomeDir, ".docker/desktop/httpproxy.sock")
	return net.Dial("unix", socket)
}
