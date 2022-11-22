package types

type BaseImage struct {
	CreatedAt  string `graphql:"createdAt" json:"created_at,omitempty"`
	Digest     string `graphql:"digest" json:"digest,omitempty"`
	Repository struct {
		Badge         string   `graphql:"badge" json:"badge,omitempty"`
		Host          string   `graphql:"hostName" json:"host,omitempty"`
		Repo          string   `graphql:"repoName" json:"repo,omitempty"`
		SupportedTags []string `graphql:"supportedTags" json:"supported_tags,omitempty"`
		PreferredTags []string `graphql:"preferredTags" json:"preferred_tags,omitempty"`
	} `graphql:"repository" json:"repository"`
	Tags []struct {
		Current   bool   `graphql:"current" json:"current"`
		Name      string `graphql:"name" json:"name,omitempty"`
		Supported bool   `graphql:"supported" json:"supported"`
	} `graphql:"tags" json:"tags,omitempty"`
	DockerFile struct {
		Commit struct {
			Repository struct {
				Org  string `graphql:"orgName" json:"org,omitempty"`
				Repo string `graphql:"repoName" json:"repo,omitempty"`
			} `graphql:"repository" json:"repository,omitempty"`
			Sha string `graphql:"sha" json:"sha,omitempty"`
		} `json:"commit,omitempty"`
		Path string `graphql:"path" json:"path,omitempty"`
	} `graphql:"dockerFile" json:"docker_file,omitempty"`
	PackageCount        int `graphql:"packageCount" json:"package_count,omitempty"`
	VulnerabilityReport struct {
		Critical    int `graphql:"critical" json:"critical,omitempty"`
		High        int `graphql:"high" json:"high,omitempty"`
		Medium      int `graphql:"medium" json:"medium,omitempty"`
		Low         int `graphql:"low" json:"low,omitempty"`
		Unspecified int `graphql:"unspecified" json:"unspecified,omitempty"`
		Total       int `graphql:"total" json:"total,omitempty"`
	} `graphql:"vulnerabilityReport" json:"vulnerability_report"`
}

type BaseImageMatch struct {
	DiffIds []string    `graphql:"matches" json:"diff_ids,omitempty"`
	Images  []BaseImage `graphql:"images" json:"images,omitempty"`
}

type BaseImagesByDiffIdsQuery struct {
	ImagesByDiffIds []BaseImageMatch `graphql:"imagesByDiffIds(context: {}, diffIds: $diffIds)"`
}

type ImageByDigestQuery struct {
	ImageDetailsByDigest BaseImage `graphql:"imageDetailsByDigest(context: {}, digest: $digest, platform: {os: $os, architecture: $architecture, variant: $variant})"`
}
