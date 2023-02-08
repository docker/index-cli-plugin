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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	stereoscopeimage "github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
	"github.com/dustin/go-humanize"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/atomist-skills/go-skill"
	"github.com/docker/cli/cli/command"
	"github.com/docker/distribution/reference"
	"github.com/docker/index-cli-plugin/internal"
	"github.com/docker/index-cli-plugin/internal/ddhttp"
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
	Id     string
	Digest string
	Name   string
	Tags   []string

	Image     *v1.Image
	Source    *source.Source
	ImagePath string
	Ref       *name.Reference

	remote        bool
	copy          bool
	cli           command.Cli
	sourceCleanup func()
}

func (c *ImageCache) StoreImage() error {
	if !c.copy {
		return nil
	}
	skill.Log.Debugf("Copying image to %s", c.ImagePath)
	var imageSource stereoscopeimage.Source

	if format := os.Getenv("ATOMIST_CACHE_FORMAT"); format == "" || format == "oci" {
		spinner := internal.StartSpinner("info", "Copying image", c.cli.Out().IsTerminal())
		defer spinner.Stop()
		p, err := layout.FromPath(c.ImagePath)
		if err != nil {
			p, err = layout.Write(c.ImagePath, empty.Index)
			if err != nil {
				return err
			}
		}
		if err = p.AppendImage(*c.Image); err != nil {
			return err
		}

		imageSource = stereoscopeimage.OciDirectorySource

		spinner.Stop()
	} else if format == "tar" {
		if c.remote {
			u := make(chan v1.Update)
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
			spinner := internal.StartSpinner("info", "Copying image", c.cli.Out().IsTerminal())
			defer spinner.Stop()
			loop := true
			for loop {
				select {
				case update = <-u:
					if update.Total > 0 {
						p := 100 * update.Complete / update.Total
						if pp != p {
							spinner.WithFields(internal.Fields{
								"event":    "progress",
								"total":    update.Total,
								"complete": update.Complete,
							}).Update(fmt.Sprintf("Copying image %d%% %s/%s", p, humanize.Bytes(uint64(update.Complete)), humanize.Bytes(uint64(update.Total))))
							pp = p
						}
					}
				case err = <-errchan:
					if err != nil {
						return err
					} else {
						spinner.Stop()
						skill.Log.Infof("Copied image")
						loop = false
					}
				}
			}
		} else {
			spinner := internal.StartSpinner("info", "Copying image", c.cli.Out().IsTerminal())
			defer spinner.Stop()
			tempTarFile, err := os.Create(c.ImagePath)
			if err != nil {
				return errors.Wrap(err, "unable to create temp file for image")
			}
			defer func() {
				err := tempTarFile.Close()
				if err != nil {
					skill.Log.Errorf("unable to close temp file (%s): %v", tempTarFile.Name(), err)
				}
			}()

			readCloser, err := c.cli.Client().ImageSave(context.Background(), []string{c.Id})
			if err != nil {
				return errors.Wrap(err, "unable to save image tar")
			}
			defer func() {
				err := readCloser.Close()
				if err != nil {
					skill.Log.Errorf("unable to close temp file (%s): %v", tempTarFile.Name(), err)
				}
			}()

			nBytes, err := io.Copy(tempTarFile, readCloser)
			if err != nil {
				return fmt.Errorf("unable to save image to tar: %w", err)
			}
			if nBytes == 0 {
				return errors.New("cannot provide an empty image")
			}
			spinner.Stop()
		}

		imageSource = stereoscopeimage.DockerTarballSource
	}

	skill.Log.Debugf("Parsing image")
	input := source.Input{
		Scheme:      source.ImageScheme,
		ImageSource: imageSource,
		Location:    c.ImagePath,
	}
	src, cleanup, err := source.New(input, nil, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create new image source")
	}
	c.Source = src
	c.sourceCleanup = cleanup

	skill.Log.Debugf("Parsed image")
	skill.Log.Infof("Copied image")

	return nil
}

func (c *ImageCache) Cleanup() {
	if c.sourceCleanup != nil {
		c.sourceCleanup()
	}
	if !c.copy {
		return
	}
	e := os.RemoveAll(c.ImagePath)
	if e != nil {
		skill.Log.Warnf("Failed to delete tmp image archive %s: %v", c.ImagePath, e)
	}
}

// SaveImage stores the v1.Image at path returned in OCI format
func SaveImage(image string, username string, password string, cli command.Cli) (*ImageCache, error) {
	skill.Log.Infof("Requesting image %s", image)
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse reference: %s", image)
	}

	createPaths := func(digest string) (string, error) {
		var path string
		if v, ok := os.LookupEnv("ATOMIST_CACHE_DIR"); ok {
			path = filepath.Join(v, "docker-index")
		} else {
			path = filepath.Join(os.TempDir(), "docker-index")
		}
		tarPath := filepath.Join(path, "sha256", digest[7:])
		tarFileName := filepath.Join(tarPath, uuid.NewString())
		if os.Getenv("ATOMIST_CACHE_FORMAT") != "oci" {
			tarFileName += ".tar"
		}

		if _, err := os.Stat(tarPath); !os.IsNotExist(err) {
			return tarFileName, nil
		}
		err := os.MkdirAll(tarPath, os.ModePerm)
		if err != nil {
			return "", err
		}
		return tarFileName, nil
	}

	// check local first because it is the fastest
	im, _, err := cli.Client().ImageInspectWithRaw(context.Background(), image)
	if err == nil {
		img, err := daemon.Image(ImageId{name: image}, daemon.WithClient(cli.Client()))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to pull image: %s", image)
		}
		imagePath, err := createPaths(im.ID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create cache paths")
		}
		var name, digest string
		tags := make([]string, 0)
		for _, d := range im.RepoDigests {
			name, digest = mustParseNameAndDigest(d)
		}
		for _, t := range im.RepoTags {
			var tag string
			name, tag = mustParseNameAndTag(t)
			tags = append(tags, tag)
		}

		return &ImageCache{
			Id:     im.ID,
			Digest: digest,
			Name:   name,
			Tags:   tags,

			Image:     &img,
			Ref:       &ref,
			ImagePath: imagePath,
			copy:      true,
			remote:    false,
			cli:       cli,
		}, nil
	}
	// try remote image next
	desc, err := remote.Get(ref, WithAuth(username, password), remote.WithTransport(ddhttp.DefaultTransport()))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to pull image: %s", image)
	}
	img, err := desc.Image()
	if err != nil {
		ix, err := remote.Index(ref, WithAuth(username, password))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to pull index: %s", image)
		}
		manifest, _ := ix.IndexManifest()
		imageRef, _ := name.ParseReference(fmt.Sprintf("%s@%s", ref.Name(), manifest.Manifests[0].Digest.String()))
		img, err = remote.Image(imageRef, WithAuth(username, password))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to pull image: %s", image)
		}
	}
	var digest string
	tags := make([]string, 0)
	identifier := ref.Identifier()
	if strings.HasPrefix(identifier, "sha256:") {
		digest = identifier
	} else {
		digestHash, _ := img.Digest()
		digest = digestHash.String()
		tags = append(tags, identifier)
	}
	imagePath, err := createPaths(digest)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create cache paths")
	}
	return &ImageCache{
		Id:     digest,
		Digest: digest,
		Name:   image,
		Image:  &img,
		Tags:   tags,

		Ref:       &ref,
		ImagePath: imagePath,
		copy:      true,
		remote:    true,
		cli:       cli,
	}, nil
}

func WithAuth(username string, password string) remote.Option {
	// check passed username and password
	if username != "" && password != "" {
		return remote.WithAuth(&authn.Basic{
			Username: username,
			Password: password,
		})
	}
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

func mustParseNameAndTag(imageRef string) (string, string) {
	parsed, err := reference.Parse(imageRef)
	if err != nil {
		panic("expected imageRef to be a NamedTagged reference")
	}
	tagged, ok := parsed.(reference.NamedTagged)
	if !ok {
		panic("expected imageRef to be a NamedTagged reference")
	}
	return tagged.Name(), tagged.Tag()
}

func mustParseNameAndDigest(imageRef string) (string, string) {
	parsed, err := reference.Parse(imageRef)
	if err != nil {
		panic("expected imageRef to be a Canonical reference")
	}
	canonical, ok := parsed.(reference.Canonical)
	if !ok {
		panic("expected imageRef to be a Canonical reference")
	}
	return canonical.Name(), canonical.Digest().String()
}
