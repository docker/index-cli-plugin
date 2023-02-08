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

package query

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/hasura/go-graphql-client"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	"github.com/pkg/errors"
	"olympos.io/encoding/edn"

	"github.com/atomist-skills/go-skill"
	"github.com/docker/index-cli-plugin/internal/ddhttp"
	"github.com/docker/index-cli-plugin/types"
)

type ImageQueryResult struct {
	Query struct {
		Data [][]types.Image `edn:"data"`
	} `edn:"query"`
}

type RepositoryQueryResult struct {
	Query struct {
		Data [][]types.Repository `edn:"data"`
	} `edn:"query"`
}

//go:embed base_image_query.edn
var baseImageQuery string

//go:embed base_image_cve_query.edn
var baseImageCveQuery string

//go:embed repository_query.edn
var repositoryQuery string

func Detect(sb *types.Sbom, excludeSelf bool, workspace string, apiKey string) (*[]types.Image, int, error) {
	digests := make([]digest.Digest, 0)
	layers := (*sb).Source.Image.Config.RootFS.DiffIDs
	for _, layer := range layers {
		parsed, _ := digest.Parse(layer.String())
		digests = append(digests, parsed)
	}
	if excludeSelf {
		digests = digests[0 : len(digests)-1]
	}

	chainIds := make([]digest.Digest, 0)
	var images *[]types.Image
	var index int
	for i := range digests {
		chainIds = append(chainIds, digests[i])
		chainId := identity.ChainID(chainIds)
		result, err := ForBaseImageInDb(chainId, workspace, apiKey)
		if err != nil || result == nil {
			result, err = ForBaseImageInIndex(chainId, workspace, apiKey)
			if err != nil {
				return nil, -1, err
			}
		}
		if result != nil {
			images = result
			index = i
		}
	}
	return images, index, nil
}

func ForBaseImageInIndex(digest digest.Digest, workspace string, apiKey string) (*[]types.Image, error) {
	url := fmt.Sprintf("https://api.dso.docker.com/docker-images/chain-ids/%s.json", digest.String())

	resp, err := ddhttp.DefaultClient().Get(url)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query index")
	}

	if resp.StatusCode == 200 {
		var manifestList []types.IndexManifestList
		defer resp.Body.Close() //nolint:errcheck
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read response body")
		}
		err = json.Unmarshal(body, &manifestList)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal response body")
		}
		var ii types.IndexImage
		for _, i := range manifestList[0].Images {
			if i.DigestChainId == digest.String() || i.DiffIdChainId == digest.String() {
				ii = i
				break
			}
		}
		repository, err := ForRepositoryInDb(manifestList[0].Name, workspace, apiKey)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to query for repository")
		}
		image := types.Image{
			Digest:     ii.Digest,
			CreatedAt:  ii.CreatedAt,
			Tags:       manifestList[0].Tags,
			Repository: *repository,
			Report: []types.Report{{
				Total: -1,
			}},
		}
		return &[]types.Image{image}, nil
	}

	return nil, nil
}

func ForBaseImageWithoutCve(cve string, name string, sb *types.Sbom, workspace string, apiKey string) (*[]types.Image, error) {
	cf := (*sb).Source.Image.Config
	resp, err := query(fmt.Sprintf(baseImageCveQuery, cve, name, cf.OS, cf.Architecture, cf.Variant), "base_image_cve_query", workspace, apiKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query for base image without CVE")
	}

	var result ImageQueryResult
	defer resp.Body.Close() //nolint:errcheck
	err = edn.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal response")
	}
	if len(result.Query.Data) > 0 {
		images := make([]types.Image, 0)

		for _, img := range result.Query.Data {
			tba := true
			for j := range images {
				if images[j].Digest == img[0].Digest && img[0].TeamId == "A11PU8L1C" {
					images[j] = img[0]
					tba = false
					break
				}
			}
			if tba {
				images = append(images, img[0])
			}
		}
		sort.Slice(images, func(i, j int) bool {
			itag := types.Tags(&images[i])[0]
			jtag := types.Tags(&images[j])[0]
			both := []string{itag, jtag}
			sort.Strings(both)
			return both[0] == itag
		})
		return &images, nil
	} else {
		return nil, nil
	}
}

// ForBaseImageInDb returns images with matching digest in :docker.image/blob-digest or :docker.image/diff-chain-id
func ForBaseImageInDb(digest digest.Digest, workspace string, apiKey string) (*[]types.Image, error) {
	resp, err := query(fmt.Sprintf(baseImageQuery, digest), "base_image_query", workspace, apiKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query for base image in DB")
	}

	var result ImageQueryResult
	defer resp.Body.Close() //nolint:errcheck
	err = edn.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal response")
	}
	if len(result.Query.Data) > 0 {
		images := make([]types.Image, 0)

		for _, img := range result.Query.Data {
			tba := true
			for j := range images {
				if images[j].Digest == img[0].Digest && img[0].TeamId == "A11PU8L1C" {
					images[j] = img[0]
					tba = false
					break
				}
			}
			if tba {
				images = append(images, img[0])
			}
		}
		return &images, nil
	} else {
		return nil, nil
	}
}

func ForRepositoryInDb(repo string, workspace string, apiKey string) (*types.Repository, error) {
	resp, err := query(fmt.Sprintf(repositoryQuery, repo), "repository_query", workspace, apiKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query for repository in DB")
	}

	var result RepositoryQueryResult
	defer resp.Body.Close() //nolint:errcheck
	err = edn.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal response")
	}
	if len(result.Query.Data) > 0 {
		return &result.Query.Data[0][0], nil
	} else {
		return nil, nil
	}
}

func ForBaseImageInGraphQL(cfg *v1.ConfigFile) (*types.BaseImagesByDiffIdsQuery, error) {
	diffIds := make([]graphql.ID, 0)
	for _, d := range cfg.RootFS.DiffIDs {
		diffIds = append(diffIds, graphql.ID(d.String()))
	}

	if len(diffIds) == 0 {
		return nil, nil
	}

	url := "https://api.dso.docker.com/v1/graphql"
	client := graphql.NewClient(url, ddhttp.DefaultClient())
	variables := map[string]interface{}{
		"diffIds": diffIds,
	}

	var q types.BaseImagesByDiffIdsQuery
	err := client.Query(context.Background(), &q, variables)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to run query")
	}
	count := 0
	for ii := range q.ImagesByDiffIds {
		for bi := range q.ImagesByDiffIds[ii].Images {
			count++
			q.ImagesByDiffIds[ii].Images[bi].Repository = normalizeRepository(&q.ImagesByDiffIds[ii].Images[bi]).Repository
		}
	}
	if count == 1 {
		skill.Log.Infof("Detected %d base image", count)
	} else {
		skill.Log.Infof("Detected %d base images", count)
	}
	return &q, nil
}

func ForImageInGraphQL(sb *types.Sbom) (*types.ImageByDigestQuery, error) {
	url := "https://api.dso.docker.com/v1/graphql"
	client := graphql.NewClient(url, ddhttp.DefaultClient())
	variables := map[string]interface{}{
		"digest":       sb.Source.Image.Digest,
		"os":           sb.Source.Image.Platform.Os,
		"architecture": sb.Source.Image.Platform.Architecture,
		"variant":      sb.Source.Image.Platform.Variant,
	}
	if sb.Source.Image.Platform.Variant == "" {
		variables["variant"] = "n/a"
	}
	skill.Log.Debugf("Querying for image with %v", variables)

	var q types.ImageByDigestQuery
	err := client.Query(context.Background(), &q, variables)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to run query")
	}
	if q.ImageDetailsByDigest.Digest != "" {
		q.ImageDetailsByDigest.Repository = normalizeRepository(&q.ImageDetailsByDigest).Repository
	}
	skill.Log.Debugf("Image query returned %v", q)
	return &q, nil
}

func normalizeRepository(image *types.BaseImage) *types.BaseImage {
	if image.Repository.Host == "hub.docker.com" && !strings.Contains(image.Repository.Repo, "/") {
		image.Repository.Badge = "OFFICIAL"
	}
	if image.Repository.Badge != "" {
		image.Repository.Badge = strings.ToLower(image.Repository.Badge)
	}
	return image
}
