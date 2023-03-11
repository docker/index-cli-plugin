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

package types

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"

	"github.com/atomist-skills/go-skill"
)

func NormalizePackages(pkgs []Package) ([]Package, error) {
	nPks := make([]Package, 0)
	for i := range pkgs {
		pkg := pkgs[i]
		purl, err := ToPackageUrl(pkg.Purl)
		if err != nil {
			skill.Log.Warnf("Failed to parse purl: %s", pkg.Purl)
			continue
		}
		if purl.Type == "" || purl.Name == "" {
			skill.Log.Warnf("Incomplete purl: %s", pkg.Purl)
			continue
		}
		purl.Namespace = toNamespace(purl)

		// some version strings (e.g. such of Go) have a v prefix that we drop
		purl.Version = strings.TrimPrefix(purl.Version, "v")
		if purl.Version == "" {
			purl.Version = "0.0.0"
		}

		// select the qualifiers we support
		if q := purl.Qualifiers.Map(); len(q) > 0 {
			qualifiers := make(map[string]string, 0)
			qualifiers["os_name"] = q["os_name"]
			qualifiers["os_version"] = q["os_version"]
			if d := q["os_distro"]; d != "" {
				qualifiers["os_distro"] = d
			}
			if d := q["distro_name"]; d != "" {
				qualifiers["distro_name"] = d
			}
			if d := q["distro_version"]; d != "" {
				qualifiers["distro_version"] = d
			}
			purl.Qualifiers = packageurl.QualifiersFromMap(qualifiers)
		}

		// filter out duplicate locations
		locations := make([]Location, 0)
		for _, loc := range pkg.Locations {
			if !containsLocation(locations, loc.Path) {
				locations = append(locations, loc)
			}
		}
		pkg.Locations = locations

		// filter out duplicate files
		files := make([]Location, 0)
		for _, f := range pkg.Files {
			if !containsLocation(files, f.Path) {
				files = append(files, f)
			}
		}
		pkg.Files = files

		// parse license expressions into list of strings
		pkg.Licenses = parseLicenses(pkg.Licenses)

		// fill in missing details
		pkg.Type = purl.Type
		pkg.Namespace = purl.Namespace
		pkg.Name = purl.Name
		pkg.Version = purl.Version
		pkg.Purl = purl.String()

		nPks = append(nPks, pkg)
	}
	return nPks, nil
}

func ToPackageUrl(url string) (packageurl.PackageURL, error) {
	url = strings.TrimSuffix(url, "/")
	purl, err := packageurl.FromString(url)
	return purl, err
}

func PackageToPackageUrl(pkp Package) *packageurl.PackageURL {
	return packageurl.NewPackageURL(pkp.Type, pkp.Namespace, pkp.Name, pkp.Version, packageurl.QualifiersFromMap(make(map[string]string)), "")
}

func toNamespace(purl packageurl.PackageURL) string {
	if v, ok := NamespaceMapping[purl.Namespace]; ok {
		return v
	}
	return purl.Namespace
}

func parseLicenses(licenses []string) []string {
	lic := make([]string, 0)
	for _, license := range licenses {
		lic = append(lic, parseLicense(license)...)
	}
	return lic
}

func parseLicense(license string) []string {
	license = strings.TrimSpace(license)
	if strings.HasPrefix(license, "(") && strings.HasSuffix(license, ")") {
		license = license[1 : len(license)-1]
		return parseLicense(license)
	} else if parts := strings.SplitN(license, " OR ", 2); len(parts) > 1 {
		lic := []string{strings.TrimSpace(parts[0])}
		lic = append(lic, parseLicense(parts[1])...)
		return lic
	} else if parts := strings.SplitN(license, " AND ", 2); len(parts) > 1 {
		lic := []string{strings.TrimSpace(parts[0])}
		lic = append(lic, parseLicense(parts[1])...)
		return lic
	} else if parts := strings.SplitN(license, " or ", 2); len(parts) > 1 {
		lic := []string{strings.TrimSpace(parts[0])}
		lic = append(lic, parseLicense(parts[1])...)
		return lic
	} else if parts := strings.SplitN(license, " and ", 2); len(parts) > 1 {
		lic := []string{strings.TrimSpace(parts[0])}
		lic = append(lic, parseLicense(parts[1])...)
		return lic
	} else {
		return []string{license}
	}
}

func ToAdvisoryUrl(pkg Package) string {
	namespace := pkg.Namespace
	if namespace == "centos" && pkg.Type == "rpm" {
		namespace = "redhatlinux"
	}

	purl, _ := ToPackageUrl(pkg.Purl)
	osName := purl.Qualifiers.Map()["os_name"]
	osVersion := purl.Qualifiers.Map()["os_version"]
	if osName == "centos" {
		osName = "redhatlinux"
	}

	adv := fmt.Sprintf("adv:%s", pkg.Type)
	if namespace != "" {
		adv += "/" + namespace
	}
	adv += "/" + pkg.Name
	if osName != "" && osVersion != "" {
		adv += fmt.Sprintf("?os_name=%s&os_version=%s", osName, osVersion)
	}

	return strings.ToLower(adv)
}

func MergePackages(results ...IndexResult) []Package {
	packages := make([]Package, 0)
	for _, result := range results {
		if result.Status != Success {
			skill.Log.Warnf(`Failed to index image with %s: %s`, result.Name, result.Error)
			continue
		}
		for _, pkg := range result.Packages {
			if p, ok := containsPackage(&packages, pkg); ok {
				for _, loc := range pkg.Locations {
					if !containsLocation(packages[p].Locations, loc.Path) {
						packages[p].Locations = append(packages[p].Locations, loc)
					}
				}
				for _, file := range pkg.Files {
					if !containsLocation(packages[p].Files, file.Path) {
						packages[p].Files = append(packages[p].Files, file)
					}
				}
			} else {
				packages = append(packages, pkg)
			}
		}
	}
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Purl < packages[j].Purl
	})
	return packages
}

func FilterGenericPackages(packages []Package) []Package {
	pkgs := make([]Package, 0)
	genericPkgs := make([]Package, 0)
	for _, pkg := range packages {
		if pkg.Type != "generic" {
			pkgs = append(pkgs, pkg)
		} else {
			genericPkgs = append(genericPkgs, pkg)
		}
	}
	for _, pkg := range genericPkgs {
		found := false
		for _, loc := range pkg.Locations {
			for _, p := range pkgs {
				if containsLocation(p.Locations, loc.Path) || containsLocation(p.Files, loc.Path) {
					found = true
				}
			}
		}
		for _, loc := range pkg.Files {
			for _, p := range pkgs {
				if containsLocation(p.Locations, loc.Path) || containsLocation(p.Files, loc.Path) {
					found = true
				}
			}
		}
		if !found {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs
}

func containsPackage(packages *[]Package, pkg Package) (int, bool) {
	for i, p := range *packages {
		if p.Purl == pkg.Purl {
			return i, true
		}
	}
	return -1, false
}

func containsLocation(locations []Location, path string) bool {
	for _, loc := range locations {
		if loc.Path == path {
			return true
		}
	}
	return false
}
