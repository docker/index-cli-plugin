/*
 * Copyright © 2022 Docker, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package registry

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
)

type ImageId struct {
	name string
}

func (i ImageId) Context() name.Repository {
	return name.Repository{}
}

func (i ImageId) Identifier() string {
	return i.name
}

func (i ImageId) Name() string {
	return i.name
}

func (i ImageId) Scope(s string) string {
	return ""
}

func (i ImageId) String() string {
	return i.name
}

// SaveImage stores the v1.Image at path returned in OCI format
func SaveImage(image string, client client.APIClient) (v1.Image, string, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to parse reference: %s", image)
	}

	var path string
	if v, ok := os.LookupEnv("ATOMIST_CACHE_DIR"); ok {
		path = filepath.Join(v, "docker-index")
	} else {
		path = filepath.Join(os.TempDir(), "docker-index")
	}

	desc, err := remote.Get(ref, withAuth())
	if err != nil {
		img, err := daemon.Image(ImageId{name: image}, daemon.WithClient(client))
		if err != nil {
			return nil, "", errors.Wrapf(err, "failed to pull image: %s", image)
		} else {
			path, err = saveOci(img, ref, path)
			if err != nil {
				return nil, "", errors.Wrapf(err, "failed to save image: %s", image)
			}
		}
		return img, path, nil
	} else {
		img, err := desc.Image()
		if err != nil {
			return nil, "", errors.Wrapf(err, "failed to pull image: %s", image)
		}
		path, err = saveOci(img, ref, path)
		if err != nil {
			return nil, "", errors.Wrapf(err, "failed to save image: %s", image)
		}
		return img, path, nil
	}
}

// saveOci writes the v1.Image img as an OCI Image Layout at path. If a layout
// already exists at that path, it will add the image to the index.
func saveOci(img v1.Image, ref name.Reference, path string) (string, error) {
	var digest string
	identifier := ref.Identifier()
	if strings.HasPrefix(identifier, "sha256:") {
		digest = identifier
	} else {
		digestHash, _ := img.Digest()
		digest = digestHash.String()
	}
	finalPath := strings.Replace(filepath.Join(path, digest), ":", string(os.PathSeparator), 1)
	if _, err := os.Stat(finalPath); !os.IsNotExist(err) {
		return finalPath, nil
	}
	err := os.MkdirAll(finalPath, os.ModePerm)
	if err != nil {
		return "", err
	}
	p, err := layout.FromPath(finalPath)
	if err != nil {
		p, err = layout.Write(finalPath, empty.Index)
		if err != nil {
			return "", err
		}
	}
	if err = p.AppendImage(img); err != nil {
		return "", err
	}
	return finalPath, nil
}

func withAuth() remote.Option {
	// check registry token env var
	if token, ok := os.LookupEnv("ATOMIST_REGISTRY_TOKEN"); ok {
		return remote.WithAuth(&authn.Bearer{Token: token})
		// check user
	} else if user, ok := os.LookupEnv("ATOMIST_REGISTRY_USER"); ok {
		if password, ok := os.LookupEnv("ATOMIST_REGISTRY_PASSWORD"); ok {
			return remote.WithAuth(&authn.Basic{
				Username: user,
				Password: password,
			})
		}
	}
	return remote.WithAuthFromKeychain(authn.DefaultKeychain)
}
