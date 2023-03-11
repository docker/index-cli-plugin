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
	"regexp"
	"strconv"
	"strings"

	"github.com/anchore/syft/syft/source"

	"github.com/docker/index-cli-plugin/types"
)

type PackageDetector = func(packages []types.Package, image *source.Source, lm *types.LayerMapping) []types.Package

var detectors []PackageDetector

func init() {
	detectors = []PackageDetector{}
}

func AdditionalPackages(packages []types.Package, image *source.Source, lm *types.LayerMapping) []types.Package {
	additionalPackages := make([]types.Package, 0)
	for _, d := range detectors {
		additionalPackages = append(additionalPackages, d(packages, image, lm)...)
	}
	return additionalPackages
}

func stringsNodeDetector(executable string, versionEnvVar string, expr *regexp.Regexp, pkg types.Package, filterFunc func(purl string) bool) PackageDetector {
	return func(packages []types.Package, image *source.Source, lm *types.LayerMapping) []types.Package {
		// Already found via package manager
		for _, p := range packages {
			if filterFunc(p.Purl) {
				return []types.Package{}
			}
		}

		var path []string
		var version string

		env := image.Image.Metadata.Config.Config.Env
		for _, e := range env {
			k := strings.Split(e, "=")[0]
			v := strings.Split(e, "=")[1]
			switch k {
			case versionEnvVar:
				version = v
			case "PATH":
				path = strings.Split(v, ":")
			}
		}

		if len(path) > 0 {
			res, _ := image.FileResolver(source.SquashedScope)
			for _, p := range path {
				fp := fmt.Sprintf("%s/%s", p, executable)
				if locations, err := res.FilesByPath(fp); err == nil && len(locations) > 0 {
					loc := locations[0]

					if version == "" {
						f, _ := res.FileContentsByLocation(loc)
						values := readStrings(f, expr)
						if len(values) > 0 {
							version = values[0][1]
						}
					}

					if version == "" {
						continue
					}

					pkg.Version = version
					pkg.Purl = types.PackageToPackageUrl(pkg).String()
					pkg.Locations = []types.Location{{
						Path:   fp,
						DiffId: loc.FileSystemID,
						Digest: lm.ByDiffId[loc.FileSystemID],
					}}
					return []types.Package{pkg}
				}
			}
		}

		return []types.Package{}
	}
}

var (
	min   = 6
	max   = 256
	ascii = true
)

func readStrings(reader io.ReadCloser, expr *regexp.Regexp) [][]string {
	defer reader.Close() //nolint:errcheck
	in := bufio.NewReader(reader)
	str := make([]rune, 0, max)
	filePos := int64(0)
	verify := func() [][]string {
		if len(str) >= min {
			s := string(str)
			if m := expr.FindAllStringSubmatch(s, -1); len(m) > 0 {
				return m
			}
		}
		str = str[0:0]
		return [][]string{}
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
				return [][]string{}
			}
			if !strconv.IsPrint(r) || ascii && r >= 0xFF {
				if d := verify(); len(d) > 0 {
					return d
				}
				continue
			}
			// It's printable. Keep it.
			if len(str) >= max {
				if d := verify(); len(d) > 0 {
					return d
				}
			}
			str = append(str, r)
		}
	}
}
