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
	"strings"
	"sync"

	"github.com/atomist-skills/go-skill"
	"github.com/docker/cli/cli/command"
	"github.com/docker/index-cli-plugin/internal"
	"github.com/docker/index-cli-plugin/query"
	"github.com/docker/index-cli-plugin/registry"
	"github.com/docker/index-cli-plugin/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
)

type ImageIndexResult struct {
	Input string
	Sbom  *types.Sbom
	Error error
}

func indexImageAsync(wg *sync.WaitGroup, image string, cli command.Cli, resultChan chan<- ImageIndexResult) {
	defer wg.Done()
	sbom, err := IndexImage(image, cli)
	cves, err := query.ForVulnerabilitiesInGraphQL(sbom)
	if err == nil {
		sbom.Vulnerabilities = cves.VulnerabilitiesByPackage
	}
	resultChan <- ImageIndexResult{
		Input: image,
		Sbom:  sbom,
		Error: err,
	}
}

func IndexPath(path string, name string, cli command.Cli) (*types.Sbom, error) {
	cache, err := registry.ReadImage(name, path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read image")
	}
	return indexImage(cache, cli)
}

func IndexImage(image string, cli command.Cli) (*types.Sbom, error) {
	if strings.HasPrefix(image, "sha256:") {
		configFilePath := cli.ConfigFile().Filename
		sbomFilePath := filepath.Join(filepath.Dir(configFilePath), "sbom", "sha256", image[7:], "sbom.json")
		if sbom := cachedSbom(sbomFilePath); sbom != nil {
			return sbom, nil
		}
	}
	cache, err := registry.SaveImage(image, cli)
	if err != nil {
		return nil, errors.Wrap(err, "failed to copy image")
	}
	return indexImage(cache, cli)
}

func indexImage(cache *registry.ImageCache, cli command.Cli) (*types.Sbom, error) {
	configFilePath := cli.ConfigFile().Filename
	sbomFilePath := filepath.Join(filepath.Dir(configFilePath), "sbom", "sha256", cache.Id[7:], "sbom.json")
	if sbom := cachedSbom(sbomFilePath); sbom != nil {
		return sbom, nil
	}

	err := cache.StoreImage()
	defer cache.Cleanup()
	if err != nil {
		return nil, errors.Wrap(err, "failed to copy image")
	}

	lm, err := createLayerMapping(cache)
	if err != nil {
		return nil, errors.Wrap(err, "failed to index image")
	}
	s := internal.StartSpinner("info", "Indexing", cli.Out().IsTerminal())
	defer s.Stop()
	trivyResultChan := make(chan types.IndexResult)
	syftResultChan := make(chan types.IndexResult)
	go trivySbom(cache, lm, trivyResultChan)
	go syftSbom(cache, lm, syftResultChan)

	trivyResult := <-trivyResultChan
	syftResult := <-syftResultChan

	if trivyResult.Error != nil {
		return nil, errors.Wrap(trivyResult.Error, "failed to index image")
	}
	if syftResult.Error != nil {
		return nil, errors.Wrap(syftResult.Error, "failed to index image")
	}

	trivyResult.Packages, err = types.NormalizePackages(trivyResult.Packages)
	syftResult.Packages, err = types.NormalizePackages(syftResult.Packages)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to normalize packagess: %s", cache.Name)
	}

	packages := types.MergePackages(syftResult, trivyResult)

	s.Stop()
	skill.Log.Infof(`Indexed %d packages`, len(packages))

	rawManifest := cache.Source.Image.Metadata.RawManifest
	rawConfig := cache.Source.Image.Metadata.RawConfig

	var manifest v1.Manifest
	err = json.Unmarshal(rawManifest, &manifest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal manifest")
	}

	sbom := types.Sbom{
		Artifacts: packages,
		Source: types.Source{
			Type: "image",
			Image: types.ImageSource{
				Name:        cache.Name,
				Digest:      cache.Digest,
				Manifest:    &manifest,
				Config:      &cache.Source.Image.Metadata.Config,
				RawManifest: base64.StdEncoding.EncodeToString(rawManifest),
				RawConfig:   base64.StdEncoding.EncodeToString(rawConfig),
				Distro:      syftResult.Distro,
				Platform: types.Platform{
					Os:           cache.Source.Image.Metadata.Config.OS,
					Architecture: cache.Source.Image.Metadata.Config.Architecture,
					Variant:      cache.Source.Image.Metadata.Config.Variant,
				},
				Size: cache.Source.Image.Metadata.Size,
			},
		},
		Descriptor: types.Descriptor{
			Name:        "docker-index",
			Version:     internal.FromBuild().Version,
			SbomVersion: internal.FromBuild().SbomVersion,
		},
	}

	if len(cache.Tags) > 0 {
		sbom.Source.Image.Tags = &cache.Tags
	}

	js, err := json.MarshalIndent(sbom, "", "  ")
	if err == nil {
		err = os.MkdirAll(filepath.Dir(sbomFilePath), os.ModePerm)
		if err != nil {
			return nil, errors.Wrap(err, "failed create to sbom folder")
		}
		err = os.WriteFile(sbomFilePath, js, 0644)
		if err != nil {
			return nil, errors.Wrap(err, "failed to write sbom")
		}
	}

	return &sbom, nil
}

func cachedSbom(sbomFilePath string) *types.Sbom {
	// see if we can re-use an existing sbom
	if _, ok := os.LookupEnv("ATOMIST_NO_CACHE"); !ok {
		if _, err := os.Stat(sbomFilePath); !os.IsNotExist(err) {
			var sbom types.Sbom
			b, err := os.ReadFile(sbomFilePath)
			if err == nil {
				err := json.Unmarshal(b, &sbom)
				if err == nil {
					if sbom.Descriptor.SbomVersion == internal.FromBuild().SbomVersion {
						skill.Log.Infof(`Indexed %d packages`, len(sbom.Artifacts))
						return &sbom
					}
				}
			}
		}
	}
	return nil
}

func createLayerMapping(cache *registry.ImageCache) (*types.LayerMapping, error) {
	skill.Log.Debugf("Creating layer mapping")
	lm := types.LayerMapping{
		ByDiffId:        make(map[string]string, 0),
		ByDigest:        make(map[string]string, 0),
		DiffIdByOrdinal: make(map[int]string, 0),
		DigestByOrdinal: make(map[int]string, 0),
		OrdinalByDiffId: make(map[string]int, 0),
	}

	diffIds := cache.Source.Image.Metadata.Config.RootFS.DiffIDs
	layers := cache.Source.Metadata.ImageMetadata.Layers

	for i := range layers {
		layer := layers[i]
		diffId := diffIds[i]

		lm.ByDiffId[diffId.String()] = layer.Digest
		lm.ByDigest[layer.Digest] = diffId.String()
		lm.OrdinalByDiffId[diffId.String()] = i
		lm.DiffIdByOrdinal[i] = diffId.String()
		lm.DigestByOrdinal[i] = layer.Digest
	}

	skill.Log.Debugf("Created layer mapping")
	return &lm, nil
}
