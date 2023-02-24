package sbom

import (
	"testing"

	"github.com/docker/index-cli-plugin/types"
)

func TestParseReference(t *testing.T) {
	name := "192.168.188.51:8082/kipz-docker-test/foobar@sha256:56c0fd188a5c48f38d2e8747ecbdf6962795e081906fa70fc101c4cf5d097059"
	host, name, err := parseReference(&types.Sbom{
		Source: types.Source{
			Image: types.ImageSource{Name: name},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if host != "192.168.188.51:8082" {
		t.Fatalf("expected empty host, got %s", host)
	}
	if name != "kipz-docker-test/foobar" {
		t.Fatalf("expected empty host, got %s", name)
	}
}
