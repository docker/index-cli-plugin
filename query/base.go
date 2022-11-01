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
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	"github.com/pkg/errors"
	"olympos.io/encoding/edn"
)

type IndexImage struct {
	Digest    string    `json:"digest"`
	CreatedAt time.Time `json:"createdAt"`
	Platform  struct {
		Os      string `json:"os"`
		Arch    string `json:"arch"`
		Variant string `json:"variant"`
	} `json:"platform"`
	Layers []struct {
		Digest       string    `json:"digest"`
		Size         int       `json:"size"`
		LastModified time.Time `json:"lastModified"`
	} `json:"layers"`
	DigestChainId string `json:"digestChainId"`
	DiffIdChainId string `json:"diffIdChainId"`
}

type IndexManifestList struct {
	Name   string       `json:"name"`
	Tags   []string     `json:"tags"`
	Digest string       `json:"digest"`
	Images []IndexImage `json:"images"`
}

type ManifestList struct {
	Digest string `edn:"docker.manifest-list/digest"`
	Tags   []struct {
		Name string `edn:"docker.tag/name"`
	} `edn:"docker.manifest-list/tag"`
}

type Report struct {
	Total       int64 `edn:"vulnerability.report/total"`
	Critical    int64 `edn:"vulnerability.report/critical"`
	High        int64 `edn:"vulnerability.report/high"`
	Medium      int64 `edn:"vulnerability.report/medium"`
	Low         int64 `edn:"vulnerability.report/low"`
	Unspecified int64 `edn:"vulnerability.report/unspecified"`
}

type Repository struct {
	Badge         string   `edn:"docker.repository/badge"`
	Host          string   `edn:"docker.repository/host"`
	Name          string   `edn:"docker.repository/name"`
	SupportedTags []string `edn:"docker.repository/supported-tags"`
}

type Image struct {
	TeamId    string    `edn:"atomist/team-id"`
	Digest    string    `edn:"docker.image/digest"`
	CreatedAt time.Time `edn:"docker.image/created-at"`
	Tags      []string  `edn:"docker.image/tags"`
	Tag       []struct {
		Name string `edn:"docker.tag/name"`
	} `edn:"docker.image/tag"`
	ManifestList []ManifestList `edn:"docker.image/manifest-list"`
	Repository   Repository     `edn:"docker.image/repository"`
	File         struct {
		Path string `edn:"git.file/path"`
	} `edn:"docker.image/file"`
	Commit struct {
		Sha  string `edn:"git.commit/sha"`
		Repo struct {
			Name string `edn:"git.repo/name"`
			Org  struct {
				Name string `edn:"git.org/name"`
			} `edn:"git.repo/org"`
		} `edn:"git.commit/repo"`
	} `edn:"docker.image/commit"`
	Report []Report `edn:"vulnerability.report/report"`
}

type ImageQueryResult struct {
	Query struct {
		Data [][]Image `edn:"data"`
	} `edn:"query"`
}

type RepositoryQueryResult struct {
	Query struct {
		Data [][]Repository `edn:"data"`
	} `edn:"query"`
}

//go:embed base_image_query.edn
var baseImageQuery string

//go:embed base_image_cve_query.edn
var baseImageCveQuery string

//go:embed repository_query.edn
var repositoryQuery string

func Detect(img *v1.Image, excludeSelf bool, workspace string, apiKey string) (*[]Image, int, error) {
	digests := make([]digest.Digest, 0)
	layers, _ := (*img).Layers()
	for _, layer := range layers {
		d, _ := layer.DiffID()
		parsed, _ := digest.Parse(d.String())
		digests = append(digests, parsed)
	}
	if excludeSelf {
		digests = digests[0 : len(digests)-1]
	}

	chainIds := make([]digest.Digest, 0)
	var images *[]Image
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

func ForBaseImageInIndex(digest digest.Digest, workspace string, apiKey string) (*[]Image, error) {
	url := fmt.Sprintf("https://api.dso.docker.com/docker-images/chain-ids/%s.json", digest.String())

	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query index")
	}

	if resp.StatusCode == 200 {
		var manifestList []IndexManifestList
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read response body")
		}
		err = json.Unmarshal(body, &manifestList)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal response body")
		}
		var ii IndexImage
		for _, i := range manifestList[0].Images {
			if i.DigestChainId == digest.String() || i.DiffIdChainId == digest.String() {
				ii = i
				break
			}
		}
		repository, err := ForRepositoryInDb(manifestList[0].Name, workspace, apiKey)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to query for respository")
		}
		image := Image{
			Digest:     ii.Digest,
			CreatedAt:  ii.CreatedAt,
			Tags:       manifestList[0].Tags,
			Repository: *repository,
			Report: []Report{{
				Total: -1,
			}},
		}
		return &[]Image{image}, nil
	}

	return nil, nil
}

func ForBaseImageWithoutCve(cve string, name string, img *v1.Image, workspace string, apiKey string) (*[]Image, error) {
	cf, _ := (*img).ConfigFile()
	resp, err := query(fmt.Sprintf(baseImageCveQuery, cve, name, cf.OS, cf.Architecture, cf.Variant), "base_image_cve_query", workspace, apiKey)

	var result ImageQueryResult
	err = edn.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal response")
	}
	if len(result.Query.Data) > 0 {
		images := make([]Image, 0)

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
			itag := Tags(&images[i])[0]
			jtag := Tags(&images[j])[0]
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
func ForBaseImageInDb(digest digest.Digest, workspace string, apiKey string) (*[]Image, error) {
	resp, err := query(fmt.Sprintf(baseImageQuery, digest), "base_image_query", workspace, apiKey)

	var result ImageQueryResult
	err = edn.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal response")
	}
	if len(result.Query.Data) > 0 {
		images := make([]Image, 0)

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

func ForRepositoryInDb(repo string, workspace string, apiKey string) (*Repository, error) {
	resp, err := query(fmt.Sprintf(repositoryQuery, repo), "repository_query", workspace, apiKey)

	var result RepositoryQueryResult
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
