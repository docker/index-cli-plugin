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
	"github.com/docker/index-cli-plugin/registry"
	"github.com/docker/index-cli-plugin/types"
)

func TestNodeDetector(t *testing.T) {
	cmd, _ := command.NewDockerCli()
	_, ociPath, _ := registry.SaveImage("node@sha256:2b00d259f3b07d8aa694b298a7dcf4655571aea2ab91375b5adb8e5a905d3ee2", cmd.Client())
	lm := types.LayerMapping{
		ByDiffId: make(map[string]string),
	}
	i := source.Input{
		Scheme:      source.ImageScheme,
		ImageSource: stereoscopeimage.OciDirectorySource,
		Location:    ociPath,
	}
	src, _, _ := source.New(i, nil, nil)
	packages := nodePackageDetector()([]types.Package{}, *src, lm)
	if len(packages) != 1 {
		t.Errorf("Expected package missing")
	}
	node := packages[0]
	if node.Purl != "pkg:github/nodejs/node@19.0.0" {
		t.Errorf("Wrong nodejs version detected")
	}
}
