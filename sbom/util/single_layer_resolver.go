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

package util

import (
	"fmt"
	"io"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
	"github.com/pkg/errors"
)

type singleLayerResolver struct {
	layer *image.Layer
}

func NewSingleLayerResolver(layer *image.Layer) *singleLayerResolver {
	return &singleLayerResolver{layer: layer}
}

func (r *singleLayerResolver) HasPath(path string) bool {
	p := file.Path(path)
	return r.layer.Tree.HasPath(p)
}

func (r *singleLayerResolver) FileContentsByLocation(location source.Location) (io.ReadCloser, error) {
	p := file.Path(location.RealPath)
	return r.layer.FileContents(p)
}

func (r *singleLayerResolver) FilesByPath(paths ...string) ([]source.Location, error) {
	locations := make([]source.Location, 0)
	for _, path := range paths {
		tree := r.layer.Tree
		_, ref, err := tree.File(file.Path(path), filetree.FollowBasenameLinks, filetree.DoNotFollowDeadBasenameLinks)
		if err != nil || ref == nil {
			return nil, fmt.Errorf("could not get files for path %q: %w", path, err)
		}
		locations = append(locations, source.NewLocation(ref.String()))
	}
	return locations, nil
}

func (r *singleLayerResolver) FilesByGlob(patterns ...string) ([]source.Location, error) {
	locations := make([]source.Location, 0)
	for _, pattern := range patterns {
		tree := r.layer.Tree
		refs, err := tree.FilesByGlob(pattern, filetree.FollowBasenameLinks, filetree.DoNotFollowDeadBasenameLinks)
		if err != nil || refs == nil {
			return nil, fmt.Errorf("could not get files for pattern %q: %w", pattern, err)
		}
		for _, r := range refs {
			locations = append(locations, source.NewLocation(string(r.RealPath)))
		}
	}
	return locations, nil
}

func (r *singleLayerResolver) RelativeFileByPath(_ source.Location, path string) *source.Location {
	paths, err := r.FilesByPath(path)
	if err != nil {
		return nil
	}
	if len(paths) == 0 {
		return nil
	}

	return &paths[0]
}

func (r *singleLayerResolver) AllLocations() <-chan source.Location {
	results := make(chan source.Location)
	return results
}

func (r *singleLayerResolver) FileMetadataByLocation(l source.Location) (source.FileMetadata, error) {
	return source.FileMetadata{}, errors.New("not implemented")
}

func (r *singleLayerResolver) FilesByMIMEType(types ...string) ([]source.Location, error) {
	return []source.Location{}, errors.New("not implemented")
}
