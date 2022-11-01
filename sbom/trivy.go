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
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/binary"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/mod"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/jar"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/pom"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	aimage "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/docker/index-cli-plugin/types"
	"github.com/pkg/errors"
)

func trivySbom(ociPath string, lm types.LayerMapping, resultChan chan<- types.IndexResult) {
	result := types.IndexResult{
		Name:     "trivy",
		Status:   types.Success,
		Packages: make([]types.Package, 0),
	}

	defer close(resultChan)

	cacheClient, err := initializeCache()
	if err != nil {
		result.Status = types.Failed
		result.Error = errors.Wrap(err, "failed to initialize cache")
	}
	defer cacheClient.Close()

	img, err := image.NewArchiveImage(ociPath + "/archive.tar")
	if err != nil {
		result.Status = types.Failed
		result.Error = errors.Wrap(err, "failed to open archived image")
	}

	art, err := aimage.NewArtifact(img, cacheClient, artifact.Option{})
	if err != nil {
		result.Status = types.Failed
		result.Error = errors.Wrap(err, "failed to create new artifact")
	}

	imageInfo, err := art.Inspect(context.Background())
	if err != nil {
		result.Status = types.Failed
		result.Error = errors.Wrap(err, "failed to inspect image")
	}

	a := applier.NewApplier(cacheClient)
	for v := range imageInfo.BlobIDs {
		mergedLayer, err := a.ApplyLayers(imageInfo.ID, []string{imageInfo.BlobIDs[v]})
		if err != nil {
			switch err {
			case analyzer.ErrUnknownOS, analyzer.ErrNoPkgsDetected:
			default:
				result.Status = types.Failed
				result.Error = errors.Wrap(err, "failed to inspect layer")
			}
		}
		for _, app := range mergedLayer.Applications {
			switch app.Type {
			case "gobinary":
				for _, lib := range app.Libraries {
					if lib.Version == "" || lib.Name == "" {
						continue
					}

					url := fmt.Sprintf(`pkg:golang/%s@%s`, lib.Name, lib.Version)
					purl, err := types.ToPackageUrl(url)
					if err != nil {
						result.Status = types.Failed
						result.Error = errors.Wrapf(err, "failed to create purl from %s", url)
						break
					}
					pkg := types.Package{
						Purl: purl.String(),
						Locations: []types.Location{{
							Path:   "/" + app.FilePath,
							Digest: lm.ByDiffId[lib.Layer.DiffID],
							DiffId: lib.Layer.DiffID,
						}},
					}
					result.Packages = append(result.Packages, pkg)
				}
			case "jar":
				for _, lib := range app.Libraries {
					if lib.Version == "" || !strings.Contains(lib.Name, ":") {
						continue
					}

					namespace := strings.Split(lib.Name, ":")[0]
					name := strings.Split(lib.Name, ":")[1]

					url := fmt.Sprintf(`pkg:maven/%s/%s@%s`, namespace, name, lib.Version)
					purl, err := types.ToPackageUrl(url)
					if err != nil {
						result.Status = types.Failed
						result.Error = errors.Wrapf(err, "failed to create purl from %s", url)
						break
					}
					pkg := types.Package{
						Purl: purl.String(),
						Locations: []types.Location{{
							Path:   "/" + lib.FilePath,
							Digest: lm.ByDiffId[lib.Layer.DiffID],
							DiffId: lib.Layer.DiffID,
						}},
					}
					result.Packages = append(result.Packages, pkg)
				}
			default:
			}
		}
	}
	resultChan <- result
}

func initializeCache() (cache.Cache, error) {
	var cacheClient cache.Cache
	var err error
	cacheClient, err = cache.NewFSCache(utils.CacheDir())
	return cacheClient, err
}
