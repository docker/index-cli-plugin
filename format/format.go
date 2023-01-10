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

package format

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gookit/color"
	"github.com/xeonx/timeago"

	"github.com/docker/index-cli-plugin/internal"
	"github.com/docker/index-cli-plugin/types"
)

type colors struct {
	critical    *color.RGBStyle
	high        *color.RGBStyle
	medium      *color.RGBStyle
	low         *color.RGBStyle
	unspecified *color.RGBStyle

	green  color.Color
	yellow color.Color
	cyan   color.Color

	red  color.Style
	blue color.Style

	underline color.Style
}

var defaultColors *colors

func init() {
	defaultColors = &colors{
		critical:    color.HEXStyle("white", "D52536"),
		high:        color.HEXStyle("white", "DD7805"),
		medium:      color.HEXStyle("white", "FBB552"),
		low:         color.HEXStyle("white", "FCE1A9"),
		unspecified: color.HEXStyle("white", "E9ECEF"),

		green:  color.Green,
		yellow: color.Yellow,
		cyan:   color.Cyan,

		red:  color.New(color.HiWhite, color.BgRed),
		blue: color.New(color.HiWhite, color.BgBlue),

		underline: color.New(color.OpUnderscore),
	}
}

func Image(image *types.Image, imageTags bool) string {
	e := ""
	if image.Repository.Host != "hub.docker.com" {
		e += image.Repository.Host + "/"
	}
	e += image.Repository.Name
	e = defaultColors.green.Sprintf(e)
	tags := types.Tags(image)
	if imageTags {
		tags = types.ImageTags(image)
	}
	if len(tags) > 0 {
		for i, t := range tags {
			tags[i] = defaultColors.cyan.Sprintf(t)
		}
		e += ":" + strings.Join(tags, ", ")
	}
	if oc := officialContent(image); oc != "" {
		e += " " + defaultColors.blue.Sprintf(oc)
		if st := types.SupportedTag(image); st != "" {
			e += " " + defaultColors.red.Sprintf(st)
		}
	}
	if ct := CurrentTag(image); ct != "" {
		e += " " + defaultColors.red.Sprintf(ct)
	}
	e += "\n" + image.Digest
	if cve := RenderVulnerabilities(image); cve != "" {
		e += " " + cve
	}
	e += " " + timeago.NoMax(timeago.English).Format(image.CreatedAt)
	if url := RenderCommit(image); url != "" {
		e += "\n" + url
	}
	return e
}

func officialContent(image *types.Image) string {
	switch image.Repository.Badge {
	case "open_source":
		return " Sponsored OSS "
	case "verified_publisher":
		return " Verified Publisher "
	default:
		if image.Repository.Host == "hub.docker.com" && !strings.Contains(image.Repository.Name, "/") {
			return " Docker Official Image "
		}
	}
	return ""
}

func CurrentTag(image *types.Image) string {
	currentTags := types.Tags(image)
	if len(currentTags) > 0 {
		for _, tag := range image.Tags {
			if internal.Contains(currentTags, tag) {
				return ""
			}
		}
	}
	return " tag moved "
}

func RenderCommit(image *types.Image) string {
	if image.TeamId == "A11PU8L1C" {
		return fmt.Sprintf("https://dso.docker.com/images/%s/digests/%s", image.Repository.Name, image.Digest)
	} else if image.Commit.Sha != "" {
		url := fmt.Sprintf("https://github.com/%s/%s", image.Commit.Repo.Org.Name, image.Commit.Repo.Name)
		if image.File.Path != "" {
			url = fmt.Sprintf("%s/blob/%s/%s", url, image.Commit.Sha, image.File.Path)
		}
		return url
	}
	return ""
}

func RenderVulnerabilities(image *types.Image) string {
	if len(image.Report) > 0 {
		report := image.Report[0]
		if report.Total == -1 {
			return " no CVE data available "
		}
		parts := make([]string, 0)
		if report.Critical > 0 {
			parts = append(parts, defaultColors.critical.Sprintf(" C"+strconv.FormatInt(report.Critical, 10)+" "))
		}
		if report.High > 0 {
			parts = append(parts, defaultColors.high.Sprintf(" H"+strconv.FormatInt(report.High, 10)+" "))
		}
		if report.Medium > 0 {
			parts = append(parts, defaultColors.medium.Sprintf(" M"+strconv.FormatInt(report.Medium, 10)+" "))
		}
		if report.Low > 0 {
			parts = append(parts, defaultColors.low.Sprintf(" L"+strconv.FormatInt(report.Low, 10)+" "))
		}
		if len(parts) > 0 {
			return strings.Join(parts, " ")
		}
	}
	return ""
}

func Cve(sb *types.Sbom, c *types.Cve) {
	sourceId := c.SourceId
	if c.Cve != nil {
		sourceId = c.Cve.SourceId
	}
	fmt.Println("")
	defaultColors.underline.Printf("Detected %s %s\n", sourceId, ColorizeSeverity(ToSeverity(*c)))
	fmt.Printf("https://dso.docker.com/cve/%s\n", sourceId)
	fmt.Println("")
	purl := c.Purl
	for _, p := range sb.Artifacts {
		if p.Purl == purl {
			defaultColors.cyan.Println(p.Purl)
			loc := p.Locations[0]
			for i, l := range sb.Source.Image.Config.RootFS.DiffIDs {
				if l.String() == loc.DiffId {
					h := sb.Source.Image.Config.History[i]
					fmt.Println(formatCreatedBy(h.CreatedBy))
					fmt.Printf("%d: %s\n", i, loc.Digest)
				}
			}
		}
	}
}

func Remediation(remediation []string) {
	if len(remediation) > 0 {
		fmt.Println("")
		defaultColors.underline.Println("Suggested remediation")
		for i, r := range remediation {
			fmt.Printf("\n%d. %s\n", i+1, r)
		}
	}
}

func PackageRemediation(p types.Package, c types.Cve) string {
	purl, _ := types.ToPackageUrl(p.Purl)
	if c.FixedBy != "not fixed" {
		switch purl.Type {
		case "alpine":
			return fmt.Sprintf(`Manually update package %s to %s

Add the following to your Dockerfile

# docker-start: fix for https://dso.docker.com/cve/%s
RUN apk add --no-cache \\
  %s=%s
# docker-end`, purl.Name, c.FixedBy, c.SourceId, purl.Name, c.FixedBy)
		case "deb":
			return fmt.Sprintf(`Manually update package %s to %s

Add the following to your Dockerfile

# docker-start: fix for https://dso.docker.com/cve/%s
RUN apt-get update && apt-get install -y \\
  %s=%s \\
  && apt-get clean -y \\
  && rm -rf /var/cache/apt /var/lib/apt/lists/* /tmp/* /var/tmp/*
# docker-end`, purl.Name, c.FixedBy, c.SourceId, purl.Name, c.FixedBy)
		}
	}
	return ""
}

func ColorizeStringBySeverity(value string, severity string) string {
	switch severity {
	case "CRITICAL":
		return defaultColors.critical.Sprintf(value)
	case "HIGH":
		return defaultColors.high.Sprintf(value)
	case "MEDIUM":
		return defaultColors.medium.Sprintf(value)
	case "LOW":
		return defaultColors.low.Sprintf(value)
	default:
		return value
	}
}

func ColorizeSeverity(severity string) string {
	label := fmt.Sprintf(" %s ", strings.TrimSpace(severity))
	switch severity {
	case "CRITICAL":
		return defaultColors.critical.Sprintf(label)
	case "HIGH":
		return defaultColors.high.Sprintf(label)
	case "MEDIUM":
		return defaultColors.medium.Sprintf(label)
	case "LOW":
		return defaultColors.low.Sprintf(label)
	default:
		return severity
	}
}

func ToSeverity(cve types.Cve) string {
	findSeverity := func(adv *types.Advisory) (string, bool) {
		if adv == nil {
			return "", false
		}
		for _, r := range (*adv).References {
			if r.Source == "atomist" {
				for _, s := range r.Scores {
					if s.Type == "atm_severity" {
						v := s.Value
						if v != "SEVERITY_UNSPECIFIED" {
							return v, true
						}
					}
				}
			}
		}
		return "", false
	}

	if severity, ok := findSeverity(cve.Cve); ok {
		return severity
	}
	if severity, ok := findSeverity(cve.Advisory); ok {
		return severity
	}

	return "IN TRIAGE"
}

func ToSeverityInt(cve types.Cve) int {
	severity := ToSeverity(cve)
	switch severity {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func formatCreatedBy(createdBy string) string {
	trim := func(prefix string) {
		if strings.HasPrefix(createdBy, prefix) {
			createdBy = strings.TrimSpace(createdBy[len(prefix):])
		}
	}
	trim("/bin/sh -c")
	trim("#(nop)")
	return createdBy
}
