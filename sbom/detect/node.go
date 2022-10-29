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

package detect

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/anchore/syft/syft/source"
	"github.com/docker/index-cli-plugin/types"
)

func nodePackageDetector(pkgs []types.Package, image source.Source, lm types.LayerMapping) []types.Package {
	// Already found nodejs via package manager
	for _, p := range pkgs {
		if purl, err := types.ToPackageUrl(p.Purl); err == nil && purl.Name == "nodejs" {
			return []types.Package{}
		}
	}

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

	if len(path) > 0 {
		res, _ := image.FileResolver(source.SquashedScope)
		for _, p := range path {
			fp := fmt.Sprintf("%s/node", p)
			if locations, err := res.FilesByPath(fp); err == nil && len(locations) > 0 {
				loc := locations[0]

				if nodeVersion == "" {
					f, _ := res.FileContentsByLocation(loc)
					values := readStrings(f, "node.js/v")
					if len(values) == 1 {
						nodeVersion = values[0][9:]
					}
				}

				if nodeVersion == "" {
					continue
				}

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

var (
	min   = 6
	max   = 256
	ascii = true
)

func readStrings(file io.ReadCloser, prefix string) []string {
	detected := make([]string, 0)
	in := bufio.NewReader(file)
	str := make([]rune, 0, max)
	filePos := int64(0)
	print := func() {
		if len(str) >= min {
			s := string(str)
			if strings.HasPrefix(s, prefix) {
				detected = append(detected, s)
			}
		}
		str = str[0:0]
	}
	for {
		var (
			r   rune
			wid int
			err error
		)
		for ; ; filePos += int64(wid) {
			r, wid, err = in.ReadRune()
			if err != nil {
				return detected
			}
			if !strconv.IsPrint(r) || ascii && r >= 0xFF {
				print()
				continue
			}
			// It's printable. Keep it.
			if len(str) >= max {
				print()
			}
			str = append(str, r)
		}
	}
	return detected
}
