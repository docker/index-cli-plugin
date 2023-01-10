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
	"strings"

	"github.com/docker/cli/cli/command"
	"github.com/docker/index-cli-plugin/internal"
	"github.com/docker/index-cli-plugin/query"
	"github.com/docker/index-cli-plugin/types"
)

func Cves(cve string, cves *[]types.Cve, sb *types.Sbom, remediate bool, dockerCli command.Cli, workspace string, apiKey string) {
	if len(*cves) > 0 {
		for _, c := range *cves {
			Cve(sb, &c)

			if !remediate {
				continue
			}

			remediation := make([]string, 0)
			layerIndex := -1
			for _, p := range sb.Artifacts {
				if p.Purl == c.Purl {
					loc := p.Locations[0]
					for i, l := range sb.Source.Image.Config.RootFS.DiffIDs {
						if l.String() == loc.DiffId && layerIndex < i {
							layerIndex = i
						}
					}

					if rem := PackageRemediation(p, c); rem != "" {
						remediation = append(remediation, rem)
					}
				}
			}

			// see if the package comes in via the base image
			s := internal.StartInfoSpinner("Detecting base image", dockerCli.Out().IsTerminal())
			defer s.Stop()
			baseImages, index, _ := query.Detect(sb, true, workspace, apiKey)
			s.Stop()
			var baseImage *types.Image
			if layerIndex <= index && baseImages != nil && len(*baseImages) > 0 {
				baseImage = &(*baseImages)[0]

				fmt.Println("")
				fmt.Println("installed in base image")
				fmt.Println("")
				fmt.Println(Image(baseImage, true))
			}

			if baseImage != nil {
				s := internal.StartInfoSpinner("Finding alternative base images", dockerCli.Out().IsTerminal())
				defer s.Stop()
				aBaseImage, _ := query.ForBaseImageWithoutCve(c.SourceId, baseImage.Repository.Name, sb, workspace, apiKey)
				s.Stop()

				if aBaseImage != nil && len(*aBaseImage) > 0 {
					// attempt to filter the list to only include tags we know about
					mBaseImages := make([]types.Image, 0)
					for _, bi := range *aBaseImage {
						bTags := types.Tags(&bi)
						for _, t := range baseImage.Tags {
							if internal.Contains(bTags, t) {
								mBaseImages = append(mBaseImages, bi)
								break
							}
						}
					}

					e := []string{fmt.Sprintf("Update base image\n\nAlternative base images not vulnerable to %s", c.SourceId)}
					if len(mBaseImages) > 0 {
						for _, a := range mBaseImages {
							e = append(e, Image(&a, false))
						}
					} else {
						for _, a := range *aBaseImage {
							e = append(e, Image(&a, false))
						}
					}
					remediation = append(remediation, strings.Join(e, "\n\n"))
				}
			}
			Remediation(remediation)
		}
	} else {
		fmt.Printf("%s not detected\n", cve)
	}
}
