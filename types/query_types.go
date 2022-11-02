package types

import (
	"time"
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
