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
	"os"
	"strconv"
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
	stypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/pkg/errors"

	"github.com/atomist-skills/go-skill"

	"github.com/docker/index-cli-plugin/registry"
	"github.com/docker/index-cli-plugin/types"
)

func trivySbom(cache *registry.ImageCache, lm *types.LayerMapping, resultChan chan<- types.IndexResult) {
	result := types.IndexResult{
		Name:     "trivy",
		Status:   types.Success,
		Packages: make([]types.Package, 0),
		Secrets:  make([]types.Secret, 0),
	}
	defer close(resultChan)

	cacheClient, err := initializeCache()
	if err != nil {
		result.Status = types.Failed
		result.Error = errors.Wrap(err, "failed to initialize cache")
		resultChan <- result
		return
	}
	defer cacheClient.Close() //nolint:errcheck

	img, err := image.NewArchiveImage(cache.ImagePath)
	if err != nil {
		result.Status = types.Failed
		result.Error = errors.Wrap(err, "failed to open archived image")
		resultChan <- result
		return
	}

	art, err := aimage.NewArtifact(img, cacheClient, configOptions())
	if err != nil {
		result.Status = types.Failed
		result.Error = errors.Wrap(err, "failed to create new artifact")
		resultChan <- result
		return
	}

	imageInfo, err := art.Inspect(context.Background())
	if err != nil {
		result.Status = types.Failed
		result.Error = errors.Wrap(err, "failed to inspect image")
		resultChan <- result
		return
	}

	a := applier.NewApplier(cacheClient)
	/*scanner, err := secret.NewScanner("")
	if err != nil {
		result.Status = types.Failed
		result.Error = errors.Wrap(err, "failed to create secret scanner")
		resultChan <- result
		return
	}*/

	/*config := &cache.Source.Image.Metadata.Config
	for o, h := range config.History {
		secrets := scanner.Scan(secret.ScanArgs{
			FilePath: "history",
			Content:  []byte(fmt.Sprintf("%s\n%s\n%s", h.CreatedBy, h.Author, h.Comment)),
		})
		if len(secrets.Findings) > 0 {
			result.Secrets = append(result.Secrets, convertSecretFindings(secrets, types.SecretSource{
				Type: "history",
				Location: &types.Location{
					Ordinal: o,
					Digest:  lm.DigestByOrdinal[o],
					DiffId:  lm.DiffIdByOrdinal[o],
				},
			}))
		}
	}
	for k, v := range config.Config.Labels {
		secrets := scanner.Scan(secret.ScanArgs{
			FilePath: "label",
			Content:  []byte(fmt.Sprintf("%s=%s", k, v)),
		})
		if len(secrets.Findings) > 0 {
			result.Secrets = append(result.Secrets, convertSecretFindings(secrets, types.SecretSource{
				Type: "label",
			}))
		}
	}
	for _, l := range config.Config.Env {
		secrets := scanner.Scan(secret.ScanArgs{
			FilePath: "env",
			Content:  []byte(l),
		})
		if len(secrets.Findings) > 0 {
			result.Secrets = append(result.Secrets, convertSecretFindings(secrets, types.SecretSource{
				Type: "env",
			}))
		}
	}*/
	for v := range imageInfo.BlobIDs {
		mergedLayer, err := a.ApplyLayers(imageInfo.ID, []string{imageInfo.BlobIDs[v]})
		if err != nil {
			switch err {
			case analyzer.ErrUnknownOS, analyzer.ErrNoPkgsDetected:
			default:
				result.Status = types.Failed
				result.Error = errors.Wrap(err, "failed to inspect layer")
				resultChan <- result
				return
			}
		}
		for _, s := range mergedLayer.Secrets {
			result.Secrets = append(result.Secrets, convertSecretFindings(s, types.SecretSource{
				Type: "file",
				Location: &types.Location{
					Path:    s.FilePath,
					Ordinal: lm.OrdinalByDiffId[s.Layer.DiffID],
					Digest:  lm.ByDiffId[s.Layer.DiffID],
					DiffId:  s.Layer.DiffID,
				},
			}))
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
						skill.Log.Warnf("failed to create purl from %s", url)
						continue
					}
					pkg := types.Package{
						Purl: purl.String(),
						Locations: []types.Location{{
							Path:    "/" + app.FilePath,
							Ordinal: lm.OrdinalByDiffId[lib.Layer.DiffID],
							Digest:  lm.ByDiffId[lib.Layer.DiffID],
							DiffId:  lib.Layer.DiffID,
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
						skill.Log.Warnf("failed to create purl from %s", url)
						continue
					}
					pkg := types.Package{
						Purl: purl.String(),
						Locations: []types.Location{{
							Path:    "/" + lib.FilePath,
							Ordinal: lm.OrdinalByDiffId[lib.Layer.DiffID],
							Digest:  lm.ByDiffId[lib.Layer.DiffID],
							DiffId:  lib.Layer.DiffID,
						}},
					}
					result.Packages = append(result.Packages, pkg)
				}
			default:
			}
		}
	}
	skill.Log.Debug("trivy indexing completed")
	resultChan <- result
}

func initializeCache() (cache.Cache, error) {
	return cache.NewFSCache(utils.CacheDir())
}

func configOptions() artifact.Option {
	opts := artifact.Option{
		DisabledAnalyzers: []analyzer.Type{analyzer.TypeDockerfile, analyzer.TypeSecret, analyzer.TypeHelm, analyzer.TypeTerraform, analyzer.TypeJSON, analyzer.TypeYaml},
	}
	if v, ok := os.LookupEnv("ATOMIST_OFFLINE"); ok {
		if o, err := strconv.ParseBool(v); err == nil && o {
			opts.Offline = true
		}
	}
	return opts
}

func convertSecretFindings(s stypes.Secret, source types.SecretSource) types.Secret {
	secret := types.Secret{
		Source:   source,
		Findings: make([]types.SecretFinding, 0),
	}
	for _, f := range s.Findings {
		finding := types.SecretFinding{
			RuleID:   f.RuleID,
			Category: string(f.Category),
			Title:    f.Title,
			Severity: f.Severity,
			Match:    f.Match,
		}
		if source.Type == "file" {
			finding.StartLine = f.StartLine
			finding.EndLine = f.EndLine
		}
		secret.Findings = append(secret.Findings, finding)
	}
	return secret
}
