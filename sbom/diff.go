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
	"sync"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/docker/cli/cli/command"
	"github.com/docker/index-cli-plugin/types"
)

func DiffImages(image1 string, image2 string, cli command.Cli, workspace string, apikey string) error {
	resultChan := make(chan ImageIndexResult, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go indexImageAsync(&wg, image1, IndexOptions{Cli: cli}, resultChan)
	go indexImageAsync(&wg, image2, IndexOptions{Cli: cli}, resultChan)
	wg.Wait()
	close(resultChan)

	var result1, result2 ImageIndexResult
	for result := range resultChan {
		switch result.Input {
		case image1:
			result1 = result
		case image2:
			result2 = result
		}
	}

	diffPackages(result1, result2)
	// diffCves(result1, result2)
	return nil
}

func toPackageKey(pkg types.Package) string {
	if pkg.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s", pkg.Type, pkg.Namespace, pkg.Name)
	} else {
		return fmt.Sprintf("%s/%s", pkg.Type, pkg.Name)
	}
}

func toImageName(result ImageIndexResult) string {
	imageName := result.Sbom.Source.Image.Name
	imageName = strings.TrimPrefix(imageName, "index.docker.io/")
	imageName = strings.TrimPrefix(imageName, "library/")
	return imageName
}

func toHeader(result1, result2 ImageIndexResult) (string, string) {
	image1 := result1.Sbom.Source.Image
	image2 := result2.Sbom.Source.Image
	if image1.Name == image2.Name {
		if image1.Tags != nil && image2.Tags != nil {
			return (*image1.Tags)[0], (*image2.Tags)[0]
		} else {
			return image1.Digest[7:17], image2.Digest[7:17]
		}
	} else {
		return toImageName(result1), toImageName(result2)
	}
}

type PackageEntry struct {
	image1 []types.Package
	image2 []types.Package
}

type PackageMap map[string]PackageEntry

func diffPackages(result1, result2 ImageIndexResult) {
	dc := 0
	packages := make(PackageMap)
	for _, p := range result1.Sbom.Artifacts {
		key := toPackageKey(p)
		if v, ok := packages[key]; ok {
			v.image1 = append(v.image1, p)
			packages[key] = v
		} else {
			packages[key] = PackageEntry{
				image1: []types.Package{p},
				image2: make([]types.Package, 0),
			}
		}
	}
	for _, p := range result2.Sbom.Artifacts {
		key := toPackageKey(p)
		if v, ok := packages[key]; ok {
			v.image2 = append(v.image2, p)
			packages[key] = v
		} else {
			packages[key] = PackageEntry{
				image1: make([]types.Package, 0),
				image2: []types.Package{p},
			}
		}
	}

	header1, header2 := toHeader(result1, result2)

	t := table.NewWriter()
	t.AppendHeader(table.Row{"Package", "Version", header1, header2})

	t.SetColumnConfigs([]table.ColumnConfig{
		{Name: "Package", AutoMerge: true},
		{Name: "Version", AutoMerge: true, Align: text.AlignRight},
		{Number: 3, Align: text.AlignCenter, AlignFooter: text.AlignCenter, AlignHeader: text.AlignCenter},
		{Number: 4, Align: text.AlignCenter, AlignFooter: text.AlignCenter, AlignHeader: text.AlignCenter},
	})

	for k, v := range packages {
		versions := make(PackageMap)
		for _, p := range v.image1 {
			key := p.Version
			if v, ok := versions[key]; ok {
				v.image1 = append(v.image1, p)
				versions[key] = v
			} else {
				versions[key] = PackageEntry{
					image1: []types.Package{p},
					image2: make([]types.Package, 0),
				}
			}
		}
		for _, p := range v.image2 {
			key := p.Version
			if v, ok := versions[key]; ok {
				v.image2 = append(v.image2, p)
				versions[key] = v
			} else {
				versions[key] = PackageEntry{
					image1: make([]types.Package, 0),
					image2: []types.Package{p},
				}
			}
		}
		for vk, vv := range versions {
			h1 := len(vv.image1)
			h2 := len(vv.image2)
			if h1 != h2 {
				var l1, l2 string
				if h1 > 0 {
					l1 = "+"
				}
				if h2 > 0 {
					l2 = "+"
				}
				dc++
				t.AppendRow(table.Row{k, vk, l1, l2})
			}
		}
	}

	t.SortBy([]table.SortBy{
		{Name: "Package", Mode: table.Asc},
		{Name: "Version", Mode: table.Asc},
	})

	t.SetPageSize(-1)
	t.SetStyle(table.StyleLight)
	t.Style().Options.SeparateRows = true
	if dc > 0 {
		fmt.Println("Package Comparison")
		fmt.Println(t.Render())
	}
}

/*type CveEntry struct {
	image1 []types.Cve
	image2 []types.Cve
}

type CveMap map[string]CveEntry

func diffCves(result1, result2 ImageIndexResult) {
	dc := 0
	cves := make(CveMap)
	for _, c := range result1.Sbom.Vulnerabilities {
		key := c.SourceId
		if v, ok := cves[key]; ok {
			v.image1 = append(v.image1, c)
			cves[key] = v
		} else {
			cves[key] = CveEntry{
				image1: []types.Cve{c},
				image2: make([]types.Cve, 0),
			}
		}
	}
	for _, c := range result2.Sbom.Vulnerabilities {
		key := c.SourceId
		if v, ok := cves[key]; ok {
			v.image2 = append(v.image2, c)
			cves[key] = v
		} else {
			cves[key] = CveEntry{
				image1: make([]types.Cve, 0),
				image2: []types.Cve{c},
			}
		}
	}

	header1, header2 := toHeader(result1, result2)

	t := table.NewWriter()
	t.AppendHeader(table.Row{"Id", "Sev", "CVE", "Severity", header1, header2})

	t.SetColumnConfigs([]table.ColumnConfig{
		{Name: "Id", Hidden: true},
		{Name: "Sev", Hidden: true},
		{Name: "CVE", AutoMerge: true},
		{Name: "Severity", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
		{Number: 5, Align: text.AlignCenter, AlignHeader: text.AlignCenter},
		{Number: 6, Align: text.AlignCenter, AlignHeader: text.AlignCenter},
	})

	for k, v := range cves {
		var cve types.Cve
		c1 := make([]string, 0)
		for _, c := range v.image1 {
			p, _ := types.ToPackageUrl(c.Purl)
			pp := fmt.Sprintf("%s\n%s", toPackageName(p), p.Version)
			if c.FixedBy != "not fixed" {
				pp += fmt.Sprintf("\n> %s", c.FixedBy)
			}
			if !internal.Contains(c1, pp) {
				c1 = append(c1, pp)
			}
			cve = c
		}
		c2 := make([]string, 0)
		for _, c := range v.image2 {
			p, _ := types.ToPackageUrl(c.Purl)
			pp := fmt.Sprintf("%s\n%s", toPackageName(p), p.Version)
			if c.FixedBy != "not fixed" {
				pp += fmt.Sprintf("\n> %s", c.FixedBy)
			}
			if !internal.Contains(c2, pp) {
				c2 = append(c2, pp)
			}
			cve = c
		}

		if len(c1) != len(c2) {
			cl := k
			if len(c2) == 0 {
				cl = defaultColors.removed.Sprintf(k)
			} else if len(c1) == 0 {
				cl = defaultColors.added.Sprintf(k)
			}
			t.AppendRow(table.Row{k, format.ToSeverityInt(cve), cl, format.ColorizeSeverity(format.ToSeverity(cve)), strings.Join(c1, "\n"), strings.Join(c2, "\n")})
			dc++
		}
	}

	t.SortBy([]table.SortBy{
		{Name: "Sev", Mode: table.Dsc},
		{Name: "Id", Mode: table.Asc},
	})

	t.SetPageSize(-1)
	t.SetStyle(table.StyleLight)
	t.Style().Options.SeparateRows = true
	if dc > 0 {
		fmt.Println("Vulnerability Comparison")
		fmt.Println(t.Render())
	}

}*/
