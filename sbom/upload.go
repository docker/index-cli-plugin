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
	"fmt"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/uuid"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	"github.com/pkg/errors"
	"olympos.io/encoding/edn"

	"github.com/atomist-skills/go-skill"

	"github.com/docker/index-cli-plugin/internal"
	"github.com/docker/index-cli-plugin/types"
)

type TransactionMaker = func() skill.Transaction

// UploadSbom transact an image and its data into the data plane
func Upload(sb *types.Sbom, workspace string, apikey string) error {
	correlationId := uuid.NewString()
	context := skill.RequestContext{
		Event: skill.EventIncoming{
			ExecutionId: correlationId,
			WorkspaceId: workspace,
			Token:       apikey,
		},
	}

	newTransaction := context.NewTransaction
	err := transactSbom(sb, newTransaction)
	if err != nil {
		return errors.Wrap(err, "failed to transact image")
	}

	return nil
}

func Send(sb *types.Sbom, entities chan<- string) error {
	correlationId := uuid.NewString()
	context := skill.RequestContext{
		Event: skill.EventIncoming{
			ExecutionId: correlationId,
		},
	}

	newTransaction := func() skill.Transaction {
		return context.NewTransactionWithTransactor(func(entitiesString string) {
			entities <- entitiesString
		})
	}
	err := transactSbom(sb, newTransaction)
	if err != nil {
		return errors.Wrap(err, "failed to transact image")
	}

	return nil
}

func transactSbom(sb *types.Sbom, newTransaction func() skill.Transaction) error {
	now := time.Now()
	host, name, err := parseReference(sb)
	if err != nil {
		return errors.Wrap(err, "failed to obtain host and repository")
	}
	config := (*sb).Source.Image.Config
	manifest := (*sb).Source.Image.Manifest

	transaction := newTransaction().Ordered()
	ports := parsePorts(config)
	env, envVars := parseEnvVars(config)
	sha := parseSha(config)
	labels := parseLabels(config)
	diffIds := diffIdChainIds(config)
	digests := digestChainIds(manifest)

	repository := skill.MakeEntity(RepositoryEntity{
		Host:      host,
		Name:      name,
		Platforms: skill.ManyRef{Add: []string{parsePlatform(sb)}},
	}, "$repo")
	transaction.AddEntities(repository)

	layers := make([]LayerEntity, 0)
	lc := 0
	for i, l := range config.History {
		if l.EmptyLayer {
			continue
		}
		blob := BlobEntity{
			Size:   manifest.Layers[lc].Size,
			Digest: manifest.Layers[lc].Digest.String(),
			DiffId: config.RootFS.DiffIDs[lc].String(),
		}
		layer := LayerEntity{
			Ordinal:     i,
			ImageDigest: sb.Source.Image.Digest,
			Blob:        blob,
			CreatedAt:   l.Created.Time,
			CreatedBy:   l.CreatedBy,
			BlobDigest:  digests[lc].String(),
			ChainId:     diffIds[lc].String(),
		}
		layers = append(layers, layer)
		lc++
	}

	image := skill.MakeEntity(ImageEntity{
		Digest:               sb.Source.Image.Digest,
		CreatedAt:            &config.Created.Time,
		Repository:           "$repo",
		Repositories:         &skill.ManyRef{Add: []string{"$repo"}},
		Labels:               &labels,
		Ports:                &ports,
		Env:                  &env,
		EnvironmentVariables: &envVars,
		Layers:               &layers,
		BlobDigest:           digests[len(digests)-1].String(),
		DiffChainId:          diffIds[len(diffIds)-1].String(),
	}, "$image")

	if sha != "" {
		image.Sha = sha
	}

	if sb.Artifacts != nil {
		image.SbomVersion = sb.Descriptor.SbomVersion
		image.SbomState = Indexing
		image.SbomLastUpdated = &now
		image.SbomPackageCount = len(sb.Artifacts)
	}

	if sb.Source.Image.Tags != nil && len(*sb.Source.Image.Tags) > 0 {
		image.Tags = &skill.ManyRef{Add: *sb.Source.Image.Tags}

		for _, t := range *sb.Source.Image.Tags {
			tag := TagEntity{
				Name:       t,
				UpdatedAt:  config.Created.Time,
				Repository: "$repo",
				Digest:     sb.Source.Image.Digest,
				Image:      "$image",
			}
			transaction.AddEntities(tag)
		}
	}

	platform := PlatformEntity{
		Image:        "$image",
		Os:           sb.Source.Image.Platform.Os,
		Architecture: sb.Source.Image.Platform.Architecture,
		Variant:      sb.Source.Image.Platform.Variant,
	}

	// transact the image with all its metadata (repo, tags, layers, blobs, ports, env etc)
	err = transaction.AddEntities(image, platform).Transact()
	if err != nil {
		return errors.Wrapf(err, "failed to transact image")
	}

	// transact all packages in chunks
	packageChunks := internal.ChunkSlice(sb.Artifacts, 20)
	for _, packages := range packageChunks {
		transaction := newTransaction().Ordered()

		image = skill.MakeEntity(ImageEntity{
			Digest: sb.Source.Image.Digest,
		}, "$image")

		for _, p := range packages {
			files := make([]FileEntity, 0)
			for _, f := range p.Locations {
				files = append(files, FileEntity{
					Id:     internal.Hash(fmt.Sprintf("%s %s %s", p.Purl, f.Path, f.Digest)),
					Path:   f.Path,
					Digest: f.Digest,
				})
			}

			pkg := PackageEntity{
				Purl:        p.Purl,
				Type:        p.Type,
				Namespace:   p.Namespace,
				Name:        p.Name,
				Version:     p.Version,
				Author:      p.Author,
				Licenses:    p.Licenses,
				Description: p.Description,
				Url:         p.Url,
				Size:        p.Size,
				AdvisoryUrl: types.ToAdvisoryUrl(p),
			}

			dep := DependencyEntity{
				Scopes:  []string{"provided"},
				Parent:  "$image",
				Package: pkg,
				Files:   files,
			}

			transaction.AddEntities(dep)
		}

		image.Dependencies = &skill.ManyRef{Add: transaction.EntityRefs("package/dependency")}
		err := transaction.AddEntities(image).Transact()
		if err != nil {
			return errors.Wrapf(err, "failed to transact packages")
		}
	}

	image = skill.MakeEntity(ImageEntity{
		Digest:    sb.Source.Image.Digest,
		SbomState: Indexed,
	}, "$image")
	if sb.Artifacts != nil {
		image.SbomState = Indexed
	}
	err = newTransaction().Ordered().AddEntities(image).Transact()
	if err != nil {
		return errors.Wrapf(err, "failed to transact packages")
	}
	return nil
}

func digestChainIds(manifest *v1.Manifest) []digest.Digest {
	digests := make([]digest.Digest, 0)
	for _, l := range manifest.Layers {
		p, _ := digest.Parse(l.Digest.String())
		digests = append(digests, p)
	}
	digests = identity.ChainIDs(digests)
	return digests
}

func diffIdChainIds(config *v1.ConfigFile) []digest.Digest {
	diffIds := make([]digest.Digest, 0)
	for _, d := range config.RootFS.DiffIDs {
		p, _ := digest.Parse(d.String())
		diffIds = append(diffIds, p)
	}
	diffIds = identity.ChainIDs(diffIds)
	return diffIds
}

func parseLabels(config *v1.ConfigFile) []LabelEntity {
	labels := make([]LabelEntity, 0)
	for k, v := range config.Config.Labels {
		labels = append(labels, LabelEntity{
			Name:  k,
			Value: v,
		})
	}
	return labels
}

func parseSha(config *v1.ConfigFile) string {
	for k, v := range config.Config.Labels {
		if k == "org.opencontainers.image.revision" {
			return v
		}
	}
	return ""
}

func parseEnvVars(config *v1.ConfigFile) ([][2]string, []EnvironmentVariableEntity) {
	env := make([][2]string, 0)
	envVars := make([]EnvironmentVariableEntity, 0)
	for _, v := range config.Config.Env {
		parts := strings.Split(v, "=")
		env = append(env, [2]string{parts[0], parts[1]})
		envVars = append(envVars, EnvironmentVariableEntity{
			Name:  parts[0],
			Value: parts[1],
		})
	}
	return env, envVars
}

func parsePorts(config *v1.ConfigFile) [][2]string {
	ports := make([][2]string, 0)
	for k, v := range config.Config.ExposedPorts {
		ports = append(ports, [2]string{k, fmt.Sprintf("%v", v)})
	}
	return ports
}

func parsePlatform(sb *types.Sbom) string {
	p := fmt.Sprintf("%s/%s", sb.Source.Image.Platform.Os, sb.Source.Image.Platform.Architecture)
	if variant := sb.Source.Image.Platform.Variant; variant != "" {
		p += fmt.Sprintf("/%s", variant)
	}
	return p
}

func parseReference(sb *types.Sbom) (string, string, error) {
	ref, err := name.ParseReference(sb.Source.Image.Name)
	if err != nil {
		return "", "", errors.Wrapf(err, "failed to parse reference: %s", sb.Source.Image.Name)
	}

	host := ref.Context().Registry.Name()
	if host == name.DefaultRegistry {
		host = "hub.docker.com"
	}
	name := ref.Context().RepositoryStr()
	name = strings.TrimPrefix(name, "library/")
	return host, name, nil
}

type PlatformEntity struct {
	skill.Entity `entity-type:"docker/platform"`
	Image        string `edn:"docker.platform/image"`
	Os           string `edn:"docker.platform/os"`
	Architecture string `edn:"docker.platform/architecture"`
	Variant      string `edn:"docker.platform/variant,omitempty"`
}

type TagEntity struct {
	skill.Entity `entity-type:"docker/tag"`
	Name         string    `edn:"docker.tag/name"`
	UpdatedAt    time.Time `edn:"docker.tag/updated-at"`
	Repository   string    `edn:"docker.tag/repository"`
	Digest       string    `edn:"docker.tag/digest"`
	Image        string    `edn:"docker.tag/image"`
}

type RepositoryEntity struct {
	skill.Entity `entity-type:"docker/repository"`
	Host         string        `edn:"docker.repository/host"`
	Name         string        `edn:"docker.repository/repository"`
	Platforms    skill.ManyRef `edn:"docker.repository/platforms"`
	Type         edn.Keyword   `edn:"docker.repository/type,omitempty"`
}

type LabelEntity struct {
	skill.Entity `entity-type:"docker.image/label"`
	Name         string `edn:"docker.image.label/name"`
	Value        string `edn:"docker.image.label/value"`
}

type EnvironmentVariableEntity struct {
	skill.Entity `entity-type:"docker.image.environment/variable"`
	Name         string `edn:"docker.image.environment.variable/name"`
	Value        string `edn:"docker.image.environment.variable/value"`
}

type LayerEntity struct {
	skill.Entity `entity-type:"docker.image/layer"`
	Ordinal      int        `edn:"docker.image.layer/ordinal"`
	ImageDigest  string     `edn:"docker.image.layer/image-digest"`
	Blob         BlobEntity `edn:"docker.image.layer/blob"`
	CreatedAt    time.Time  `edn:"docker.image.layer/created-at"`
	CreatedBy    string     `edn:"docker.image.layer/created-by"`
	BlobDigest   string     `edn:"docker.image.layer/blob-digest"`
	ChainId      string     `edn:"docker.image.layer/chain-id"`
}

type BlobEntity struct {
	skill.Entity `entity-type:"docker.image/blob"`
	Size         int64  `edn:"docker.image.blob/size"`
	Digest       string `edn:"docker.image.blob/digest"`
	DiffId       string `edn:"docker.image.blob/diff-id"`
}

type ImageEntity struct {
	skill.Entity         `entity-type:"docker/image"`
	Digest               string                       `edn:"docker.image/digest"`
	CreatedAt            *time.Time                   `edn:"docker.image/created-at,omitempty"`
	Repository           string                       `edn:"docker.image/repository,omitempty"`
	Repositories         *skill.ManyRef               `edn:"docker.image/repositories,omitempty"`
	Tags                 *skill.ManyRef               `edn:"docker.image/tags,omitempty"`
	Labels               *[]LabelEntity               `edn:"docker.image/labels,omitempty"`
	Ports                *[][2]string                 `edn:"docker.image/ports,omitempty"`
	Env                  *[][2]string                 `edn:"docker.image/env,omitempty"`
	EnvironmentVariables *[]EnvironmentVariableEntity `edn:"docker.image/environment-variables,omitempty"`
	Layers               *[]LayerEntity               `edn:"docker.image/layers,omitempty"`
	BlobDigest           string                       `edn:"docker.image/blob-digest,omitempty"`
	DiffChainId          string                       `edn:"docker.image/diff-chain-id,omitempty"`
	Sha                  string                       `edn:"docker.image/sha,omitempty"`

	SbomState        edn.Keyword `edn:"sbom/state,omitempty"`
	SbomVersion      string      `edn:"sbom/version,omitempty"`
	SbomLastUpdated  *time.Time  `edn:"sbom/last-updated,omitempty"`
	SbomPackageCount int         `edn:"sbom/package-count,omitempty"`

	Dependencies *skill.ManyRef `edn:"artifact/dependencies,omitempty"`
}

const (
	Indexing edn.Keyword = "sbom.state/INDEXING"
	Indexed  edn.Keyword = "sbom.state/INDEXED"
)

type PackageEntity struct {
	skill.Entity `entity-type:"package"`
	Purl         string   `edn:"package/url"`
	Type         string   `edn:"package/type"`
	Namespace    string   `edn:"package/namespace,omitempty"`
	Name         string   `edn:"package/name"`
	Version      string   `edn:"package/version"`
	Author       string   `edn:"package/author,omitempty"`
	Licenses     []string `edn:"package/licenses,omitempty"`
	Description  string   `edn:"package/description,omitempty"`
	Url          string   `edn:"package/homepage,omitempty"`
	Size         int      `edn:"package/size,omitempty"`
	AdvisoryUrl  string   `edn:"package/advisory-url"`
}

type FileEntity struct {
	skill.Entity `entity-type:"package/file"`
	Id           string `edn:"package.file/id"`
	Path         string `edn:"package.file/path"`
	Digest       string `edn:"package.file/digest"`
}

type DependencyEntity struct {
	skill.Entity `entity-type:"package/dependency"`
	Scopes       []string      `edn:"package.dependency/scopes"`
	Parent       string        `edn:"package.dependency/parent"`
	Package      PackageEntity `edn:"package.dependency/package"`
	Files        []FileEntity  `edn:"package.dependency/files"`
}
