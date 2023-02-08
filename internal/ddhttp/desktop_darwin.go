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
	socket := path.Join(current.HomeDir, "Library/Containers/com.docker.docker/Data/httpproxy.sock")
	return net.Dial("unix", socket)
}
