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

package lsp

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/source"
	"github.com/pkg/errors"

	"github.com/docker/index-cli-plugin/sbom"

	"github.com/docker/cli/cli/command"
	cliflags "github.com/docker/cli/cli/flags"
	"github.com/docker/index-cli-plugin/registry"
	"github.com/docker/index-cli-plugin/sbom/util"
)

type Lsp struct {
	username string
	password string
}

func New() *Lsp {
	return &Lsp{}
}

func (l *Lsp) WithAuth(username, password string) *Lsp {
	l.username = username
	l.password = password
	return l
}

func (l *Lsp) Send(image string, tx chan<- string) error {
	cmd, err := command.NewDockerCli()
	if err != nil {
		return errors.Wrap(err, "failed to create docker cli")
	}
	if err := cmd.Initialize(cliflags.NewClientOptions()); err != nil {
		return errors.Wrap(err, "failed to initialize docker cli")
	}
	sb, err := sbom.IndexImage(image, sbom.IndexOptions{
		Username: l.username,
		Password: l.password,
		Cli:      cmd,
	})
	if err != nil {
		return errors.Wrap(err, "failed to create sbom")
	}
	err = sbom.Send(sb, tx)
	if err != nil {
		return errors.Wrap(err, "failed to send sbom")
	}
	close(tx)
	return nil
}

func (l *Lsp) SendFileHashes(image string, tx chan<- string) error {
	cmd, err := command.NewDockerCli()
	if err != nil {
		return errors.Wrap(err, "failed to create docker cli")
	}
	if err := cmd.Initialize(cliflags.NewClientOptions()); err != nil {
		return errors.Wrap(err, "failed to initialize docker cli")
	}
	cache, err := registry.SaveImage(image, l.username, l.password, cmd)
	if err != nil {
		return errors.Wrap(err, "failed to copy image")
	}
	err = cache.StoreImage()
	if err != nil {
		return errors.Wrap(err, "failed to save image")
	}
	for _, layer := range cache.Source.Image.Layers {
		res := util.NewSingleLayerResolver(layer)
		refs := layer.Tree.AllFiles()
		for _, ref := range refs {
			content, err := res.FileContentsByLocation(source.NewLocation(string(ref.RealPath)))
			if err == nil {
				b, _ := io.ReadAll(content)
				content.Close() //nolint:errcheck
				h := sha256.New()
				h.Write(b)
				hash := fmt.Sprintf("sha256:%x", h.Sum(nil))
				msg := fmt.Sprintf(`{:path "%s" :hash "%s" :diff-id "%s"}`, ref.RealPath, hash, layer.Metadata.Digest)
				tx <- msg
			}
		}
	}
	close(tx)
	return nil
}
