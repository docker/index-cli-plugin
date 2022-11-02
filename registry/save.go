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
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/atomist-skills/go-skill"
	"github.com/docker/docker/client"
	"github.com/dustin/go-humanize"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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

type ImageCache struct {
	Name      string
	Path      string
	Image     *v1.Image
	ImagePath string
	Ref       *name.Reference

	copy bool
}

func (c *ImageCache) StoreImage() error {
	if !c.copy {
		return nil
	}
	skill.Log.Infof("Copying image %s", c.Name)
	skill.Log.Debugf("Copying image to %s", c.ImagePath)
	u := make(chan v1.Update, 200)
	errchan := make(chan error)
	go func() {
		if err := tarball.WriteToFile(c.ImagePath, *c.Ref, *c.Image, tarball.WithProgress(u)); err != nil {
			errchan <- errors.Wrapf(err, "failed to write tmp image archive")
		}
		errchan <- nil
	}()

	var update v1.Update
	var err error
	var pp int64
	for {
		select {
		case update = <-u:
			p := 100 * update.Complete / update.Total
			if p%10 == 0 && pp != p {
				skill.Log.WithFields(logrus.Fields{
					"event":    "copy",
					"total":    update.Total,
					"complete": update.Complete,
				}).Debugf("Copying image %3d%% %s/%s", p, humanize.Bytes(uint64(update.Complete)), humanize.Bytes(uint64(update.Total)))
				pp = p
			}
		case err = <-errchan:
			if err != nil {
				return err
			} else {
				skill.Log.WithFields(logrus.Fields{
					"event":    "copy",
					"total":    update.Total,
					"complete": update.Complete,
				}).Debugf("Copying image completed")
				skill.Log.Infof("Copied image")
				return nil
			}
		}
	}
}

func (c *ImageCache) Cleanup() {
	if !c.copy {
		return
	}
	e := os.Remove(c.ImagePath)
	if e != nil {
		skill.Log.Warnf("Failed to delete tmp image archive %s", c.ImagePath)
	}
}

// SaveImage stores the v1.Image at path returned in OCI format
func SaveImage(image string, client client.APIClient) (*ImageCache, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse reference: %s", image)
	}

	var path string
	if v, ok := os.LookupEnv("ATOMIST_CACHE_DIR"); ok {
		path = filepath.Join(v, "docker-index")
	} else {
		path = filepath.Join(os.TempDir(), "docker-index")
	}

	createPaths := func(digest string) (string, string, error) {
		finalPath := strings.Replace(filepath.Join(path, digest), ":", string(os.PathSeparator), 1)
		tarPath := filepath.Join(finalPath, "archive.tar")

		if _, err := os.Stat(tarPath); !os.IsNotExist(err) {
			return finalPath, tarPath, nil
		}
		err := os.MkdirAll(finalPath, os.ModePerm)
		if err != nil {
			return "", "", err
		}
		return finalPath, tarPath, nil
	}

	desc, err := remote.Get(ref, withAuth())
	if err != nil {
		img, err := daemon.Image(ImageId{name: image}, daemon.WithClient(client))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to pull image: %s", image)
		} else {
			im, _, err := client.ImageInspectWithRaw(context.Background(), image)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get local image: %s", image)
			}
			path, imagePath, err := createPaths(im.ID)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to create cache paths")
			}
			return &ImageCache{
				Name:      image,
				Path:      path,
				Image:     &img,
				Ref:       &ref,
				ImagePath: imagePath,
				copy:      true,
			}, nil
		}
	} else {
		img, err := desc.Image()
		if err != nil {
			return nil, errors.Wrapf(err, "failed to pull image: %s", image)
		}
		var digest string
		identifier := ref.Identifier()
		if strings.HasPrefix(identifier, "sha256:") {
			digest = identifier
		} else {
			digestHash, _ := img.Digest()
			digest = digestHash.String()
		}
		path, imagePath, err := createPaths(digest)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create cache paths")
		}
		return &ImageCache{
			Name:      image,
			Path:      path,
			Image:     &img,
			Ref:       &ref,
			ImagePath: imagePath,
			copy:      true,
		}, nil
	}
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
