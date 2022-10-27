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

package sbom

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/atomist-skills/go-skill"
	"github.com/docker/docker/client"
	"github.com/docker/index-cli-plugin/internal"
	"github.com/docker/index-cli-plugin/registry"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
)

func IndexPath(path string, name string) (*Sbom, *v1.Image, error) {
	skill.Log.Infof("Loading image from %s", path)
	img, err := registry.ReadImage(path)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to read image")
	}
	skill.Log.Infof("Loaded image")
	return indexImage(img, name, path)
}

func IndexImage(image string, client client.APIClient) (*Sbom, *v1.Image, error) {
	skill.Log.Infof("Copying image %s", image)
	img, path, err := registry.SaveImage(image, client)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to download image")
	}
	skill.Log.Infof("Copied image")
	return indexImage(img, image, path)
}

func indexImage(img v1.Image, imageName, path string) (*Sbom, *v1.Image, error) {
	// see if we can re-use an existing sbom
	sbomPath := filepath.Join(path, "sbom.json")
	if _, ok := os.LookupEnv("ATOMIST_NO_CACHE"); !ok {
		if _, err := os.Stat(sbomPath); !os.IsNotExist(err) {
			var sbom Sbom
			b, err := os.ReadFile(sbomPath)
			if err == nil {
				err := json.Unmarshal(b, &sbom)
				if err == nil {
					if sbom.Descriptor.SbomVersion == internal.FromBuild().SbomVersion && sbom.Descriptor.Version == internal.FromBuild().Version {
						skill.Log.Infof(`Indexed %d packages`, len(sbom.Artifacts))
						return &sbom, &img, nil
					}
				}
			}
		}
	}

	lm := createLayerMapping(img)
	skill.Log.Debugf("Created layer mapping")

	skill.Log.Info("Indexing")
	trivyResultChan := make(chan IndexResult)
	syftResultChan := make(chan IndexResult)
	go trivySbom(path, lm, trivyResultChan)
	go syftSbom(path, lm, syftResultChan)

	trivyResult := <-trivyResultChan
	syftResult := <-syftResultChan

	var err error
	trivyResult.Packages, err = NormalizePackages(trivyResult.Packages)
	syftResult.Packages, err = NormalizePackages(syftResult.Packages)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to normalize packagess: %s", imageName)
	}

	packages := mergePackages(syftResult, trivyResult)

	skill.Log.Infof(`Indexed %d packages`, len(packages))

	manifest, _ := img.RawManifest()
	config, _ := img.RawConfigFile()
	c, _ := img.ConfigFile()
	m, _ := img.Manifest()
	d, _ := img.Digest()

	var tag []string
	if imageName != "" {
		ref, err := name.ParseReference(imageName)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to parse reference: %s", imageName)
		}
		imageName = ref.Context().String()
		if !strings.HasPrefix(ref.Identifier(), "sha256:") {
			tag = []string{ref.Identifier()}
		}
	}

	sbom := Sbom{
		Artifacts: packages,
		Source: Source{
			Type: "image",
			Image: ImageSource{
				Name:        imageName,
				Digest:      d.String(),
				Manifest:    m,
				Config:      c,
				RawManifest: base64.StdEncoding.EncodeToString(manifest),
				RawConfig:   base64.StdEncoding.EncodeToString(config),
				Distro:      syftResult.Distro,
				Platform: Platform{
					Os:           c.OS,
					Architecture: c.Architecture,
					Variant:      c.Variant,
				},
				Size: m.Config.Size,
			},
		},
		Descriptor: Descriptor{
			Name:        "docker index",
			Version:     internal.FromBuild().Version,
			SbomVersion: internal.FromBuild().SbomVersion,
		},
	}

	if len(tag) > 0 {
		sbom.Source.Image.Tags = &tag
	}

	js, err := json.MarshalIndent(sbom, "", "  ")
	if err == nil {
		_ = os.WriteFile(sbomPath, js, 0644)
	}

	return &sbom, &img, nil
}

func createLayerMapping(img v1.Image) LayerMapping {
	lm := LayerMapping{
		ByDiffId:        make(map[string]string, 0),
		ByDigest:        make(map[string]string, 0),
		DiffIdByOrdinal: make(map[int]string, 0),
		DigestByOrdinal: make(map[int]string, 0),
		OrdinalByDiffId: make(map[string]int, 0),
	}
	config, _ := img.ConfigFile()
	diffIds := config.RootFS.DiffIDs
	manifest, _ := img.Manifest()
	layers := manifest.Layers

	for i := range layers {
		layer := layers[i]
		diffId := diffIds[i]

		lm.ByDiffId[diffId.String()] = layer.Digest.String()
		lm.ByDigest[layer.Digest.String()] = diffId.String()
		lm.OrdinalByDiffId[diffId.String()] = i
		lm.DiffIdByOrdinal[i] = diffId.String()
		lm.DigestByOrdinal[i] = layer.Digest.String()
	}

	return lm
}

func mergePackages(results ...IndexResult) []Package {
	packages := make([]Package, 0)
	for _, result := range results {
		if result.Status != Success {
			skill.Log.Warnf(`Failed to index image with %s: %s`, result.Name, result.Error)
			continue
		}
		for _, pkg := range result.Packages {
			if p, ok := containsPackage(&packages, pkg); ok {
				for _, loc := range pkg.Locations {
					if !containsLocation(packages[p].Locations, loc.Path) {
						packages[p].Locations = append(packages[p].Locations, loc)
					}
				}
				for _, file := range pkg.Files {
					if !containsLocation(packages[p].Files, file.Path) {
						packages[p].Files = append(packages[p].Files, file)
					}
				}
			} else {
				packages = append(packages, pkg)
			}
		}
	}
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Purl < packages[j].Purl
	})
	return packages
}

func containsPackage(packages *[]Package, pkg Package) (int, bool) {
	for i, p := range *packages {
		if p.Purl == pkg.Purl {
			return i, true
		}
	}
	return -1, false
}

func containsLocation(locations []Location, path string) bool {
	for _, loc := range locations {
		if loc.Path == path {
			return true
		}
	}
	return false
}
