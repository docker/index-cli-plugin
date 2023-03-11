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

package detect

import (
	"testing"

	stereoscopeimage "github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"

	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/flags"
	"github.com/docker/index-cli-plugin/registry"
	"github.com/docker/index-cli-plugin/types"
)

func TestNodeDetector(t *testing.T) {
	cmd, _ := command.NewDockerCli()
	err := cmd.Initialize(flags.NewClientOptions())
	if err != nil {
		t.Fatal(err)
	}
	cache, _ := registry.SaveImage("atomist/skill@sha256:a691a1ccfa81ab7cc6b422a53bfb9bbcea4d78873426b0389eec8f554da9b0b8", "", "", cmd)
	err = cache.StoreImage()
	if err != nil {
		t.Fatal(err)
	}
	lm := types.LayerMapping{
		ByDiffId: make(map[string]string),
	}
	i := source.Input{
		Scheme:      source.ImageScheme,
		ImageSource: stereoscopeimage.OciDirectorySource,
		Location:    cache.ImagePath,
	}
	src, _, err := source.New(i, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	packages := nodePackageDetector()([]types.Package{}, src, &lm)
	if len(packages) != 1 {
		t.Errorf("Expected package missing")
	}
	node := packages[0]
	if node.Purl != "pkg:github/nodejs/node@16.14.2" {
		t.Errorf("Wrong nodejs version detected %s", node.Version)
	}
}

func TestPythonDetector(t *testing.T) {
	cmd, _ := command.NewDockerCli()
	err := cmd.Initialize(flags.NewClientOptions())
	if err != nil {
		t.Fatal(err)
	}
	cache, _ := registry.SaveImage("atomist/skill@sha256:a691a1ccfa81ab7cc6b422a53bfb9bbcea4d78873426b0389eec8f554da9b0b8", "", "", cmd)
	err = cache.StoreImage()
	if err != nil {
		t.Fatal(err)
	}
	lm := types.LayerMapping{
		ByDiffId: make(map[string]string),
	}
	i := source.Input{
		Scheme:      source.ImageScheme,
		ImageSource: stereoscopeimage.OciDirectorySource,
		Location:    cache.ImagePath,
	}
	src, _, err := source.New(i, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	packages := pythonPackageDetector()([]types.Package{}, src, &lm)
	if len(packages) != 0 {
		t.Errorf("Nnot expected package")
	}
}
