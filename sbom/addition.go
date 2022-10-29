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

	"github.com/anchore/syft/syft/source"
	"github.com/docker/index-cli-plugin/types"
)

type PackageDetector = func(packages []types.Package, image source.Source, lm types.LayerMapping) []types.Package

var detectors []PackageDetector

func init() {
	detectors = []PackageDetector{nodePackageDetector}
}

func detectAdditionalPackages(packages []types.Package, image source.Source, lm types.LayerMapping) []types.Package {
	additionalPackages := make([]types.Package, 0)
	for _, d := range detectors {
		additionalPackages = append(additionalPackages, d(packages, image, lm)...)
	}
	return additionalPackages
}

func nodePackageDetector(_ []types.Package, image source.Source, lm types.LayerMapping) []types.Package {
	var path []string
	var nodeVersion string

	env := image.Image.Metadata.Config.Config.Env
	for _, e := range env {
		k := strings.Split(e, "=")[0]
		v := strings.Split(e, "=")[1]
		switch k {
		case "NODE_VERSION":
			nodeVersion = v
		case "PATH":
			path = strings.Split(v, ":")
		}
	}

	if nodeVersion != "" && len(path) > 0 {
		res, _ := image.FileResolver(source.SquashedScope)
		for _, p := range path {
			fp := fmt.Sprintf("%s/node", p)
			if locations, err := res.FilesByPath(fp); err == nil && len(locations) > 0 {
				loc := locations[0]
				return []types.Package{{
					Type:        "github",
					Namespace:   "nodejs",
					Name:        "node",
					Version:     nodeVersion,
					Purl:        fmt.Sprintf("pkg:github/nodejs/node@%s", nodeVersion),
					Author:      "Node.js Project",
					Description: "Node.js JavaScript runtime",
					Licenses:    []string{"MIT"},
					Url:         "https://nodejs.org",
					Locations: []types.Location{{
						Path:   fp,
						DiffId: loc.FileSystemID,
						Digest: lm.ByDiffId[loc.FileSystemID],
					}},
				}}
			}
		}
	}

	return []types.Package{}
}
