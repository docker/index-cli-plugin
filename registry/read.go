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
	stereoscopeimage "github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/pkg/errors"

	"github.com/atomist-skills/go-skill"
)

func ReadImage(name string, path string) (*ImageCache, error) {
	skill.Log.Infof("Loading image from %s", path)
	index, err := layout.ImageIndexFromPath(path)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read manifest index at %s", path)
	}
	mani, err := index.IndexManifest()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read manifest index at %s", path)
	}
	hash := mani.Manifests[0].Digest
	img, _ := index.Image(hash)

	skill.Log.Debugf("Parsing image")
	input := source.Input{
		Scheme:      source.ImageScheme,
		ImageSource: stereoscopeimage.OciDirectorySource,
		Location:    path,
	}
	src, cleanup, err := source.New(input, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new source")
	}
	skill.Log.Debugf("Parse image")
	skill.Log.Infof("Loaded image")

	return &ImageCache{
		Id:        hash.String(),
		Digest:    hash.String(),
		Tags:      []string{},
		Name:      name,
		Image:     &img,
		Source:    src,
		ImagePath: path,
		Ref:       nil,

		copy:          false,
		sourceCleanup: cleanup,
	}, nil
}
